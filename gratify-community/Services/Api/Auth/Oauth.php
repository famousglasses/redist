<?php

namespace App\Services\Api\Auth;
use App\Libraries\Patterns;
use App\Libraries\Util;
use App\Libraries\Request;
use Gratify\App;
use Gratify\StdException;

class Oauth {
	const AUTHORIZE_PATH = '/authorize';
	const ACCESS_TOKEN_LENGTH = 64;

	/**
	 * @http post
	 */
	public function getToken(App $app, array $request) {
		try {
			$no_redirect = (bool)($request['no_redirect'] ?? false);
			$no_redirect = $no_redirect || _CLI;
			$client_id = $app->assert(@$request['client_id'], 'string+', null, 'client id');
			$db = $app->getDatabase();
			$res = $db->get('auth_clients', ['client_id' => $client_id]);

			if ($res->num_rows == 0) {
				throw new StdException('invalid client id');
			}

			$client = $res->next();
			$client_scopes = explode(' ', $client['scope']);
			$redirect_url = $app->assert(@$request['redirect_url'], 'string?', null, 'redirect url');
			$scope = $app->assert(@$request['scope'], 'regex?', Patterns::SCOPE, 'scope');

			if (!$redirect_url) {
				$redirect_url = Util::url();
			}

			if (!filter_var($redirect_url, FILTER_VALIDATE_URL)) {
				throw new StdException('invalid redirect url');
			}

			if (!$no_redirect) {
				$redirect_domain = parse_url($redirect_url, PHP_URL_HOST);
				$allowed_domains = explode(',', $client['redirect_domains']);

				if (!in_array($redirect_domain, $allowed_domains)) {
					throw new StdException('redirect url not allowed');
				}
			}

			if (!empty($scope)) {
				$scopes = explode(' ', $scope);

				if (count(array_intersect($scopes, $client_scopes)) !== count($scopes)) {
					throw new StdException('scope not allowed');
				}
			} else {
				$scopes = [];
			}

			// Always included scopes
			if (!in_array('id', $scopes)) {
				$scopes[] = 'id';
			}

			$keyring = $app->getKeyring();
			$userinfo = null;
			$access_token = null;
			$grant_type = $request['grant_type'] ?? '';

			switch ($grant_type) {
				case 'password':
					$username = $request['username'] ?? '';
					$password = $request['password'] ?? '';
					$userinfo = $this->grantPassword($app, $username, $password);
					break;
				case 'client_credentials':
					$client_secret = $request['client_secret'] ?? '';
					$userinfo = $this->grantClientCredentials($app, $client_id, $client_secret);
					break;
				default:
					throw new StdException('grant type not supported');
			}

			if (empty($userinfo)) {
				throw new StdException('invalid username or password');
			}

			$session = $app->getSession();
			$access_token = $session->id();
			$id_vals = [];

			foreach ($scopes as $s) {
				$s = trim($s);
				if (!empty($s)) {
					if (isset($userinfo[$s])) {
						$id_vals[$s] = $userinfo[$s];
					}
				}
			}

			$id_vals['scope'] = $scope;
			$id_token = base64_encode(json_encode($id_vals));
			$permits = explode(' ', $userinfo['permit'] ?? '');
			$prefs = is_array(@$userinfo['prefs']) ? $userinfo['prefs'] : json_decode($userinfo['prefs'] ?? '{}', true);

			$session->set('id', $userinfo['id']);
			$session->set('role', $userinfo['role'] ?? '');
			$session->set('permits', $permits);
			$session->set('scopes', $scopes);
			$session->set('email', $userinfo['email'] ?? '');
			$session->set('prefs', $prefs);
			$session->set('access_token', $access_token);
			$session->set('id_token', $id_token);

			if (_IS_AJAX || $no_redirect) {
				return [
					'access_token' => $access_token,
					'id_token' => $id_token
				];
			}

			if ($redirect_domain === _DOMAIN) {
				$app->redirect($redirect_url);
			}

			$redirect_url = Util::url($redirect_url, [
				'id_token' => $id_token,
				'access_token' => $access_token
			]);

			$app->redirect($redirect_url);
		} catch (StdException $e) {
			if (_IS_AJAX || $no_redirect) {
				throw $e;
			}

			$redirect_url = Util::url(self::AUTHORIZE_PATH, ['error' => $e->getMessage()], false);
			$app->redirect($redirect_url);
		}
	}

	public function logout(App $app, array $request) {
		$session = $app->getSession();
		$session->end();

		if (!_IS_AJAX) {
			die(header("Location: {$_ENV['BASE_URI']}"));
		}

		return true;
	}

	private function grantPassword(App $app, string $username, string $password) {
		$db = $app->getDatabase();

		$res = $db->get('users, roles', [
			'username' => $username,
			'role' => '$roles.name'
		]);

		if ($res->num_rows == 0) {
			return null;
		}

		$row = $res->next();

		if (password_verify($password, $row['password'])) {
			return $row;
		}

		return null;
	}

	private function grantClientCredentials(App $app, string $client_id, string $client_secret) {
		$db = $app->getDatabase();

		$res = $db->get('auth_clients', [
			'client_id' => $client_id,
			'client_secret' => $client_secret
		]);

		if ($res->num_rows == 0) {
			return null;
		}

		$row = $res->next();

		return [
			'id' => $row['id']
		];
	}

	public function forgotPassword(App $app, array $request) {
		Request::requireGuest($app);

		$db = $app->getDatabase();
		$email = $app->assert(@$request['email'], 'email');
		$res = $db->get('users', ['email' => $email]);

		if ($res->num_rows == 0) {
			return true;
		}

		$user = $res->next();
		$user_id = $user['id'];
		$name = $user['name'];
		$tokenval = $app->getKeyring()->nonce(32);

		$res = $db->put('tokens', [
			'#value' => $tokenval,
			'@type' => 'reset-password',
			'user_id' => $user_id
		]);

		if ($res->num_affected == 0) {
			return true;
		}

		$template = 'emails/forgot.html';
		$subject = 'Password Recovery';
		$link = Util::url(Oauth::AUTHORIZE_PATH, ['reset' => 1, 'v' => $tokenval]);

		$app->email($email, $subject, $template, [
			'name' => $name,
			'link' => $link
		]);

		return true;
	}

	public function checkResetToken(App $app, array $request) {
		$db = $app->getDatabase();

		$tokenval = $request['tokenval'] ?? '';
		if (!preg_match('/^[a-z0-9]{32}$/i', $tokenval)) {
			throw new StdException('invalid token');
		}

		$res = $db->get('tokens, users.email', [
			'#value' => $tokenval,
			'type' => 'reset-password',
			'user_id' => '$users.id'
		]);

		if ($res->num_rows == 0) {
			throw new StdException('invalid token');
		}

		$token = $res->next();

		if (Util::isDateOlderThan(strtotime($token['created']), 1)) {
			throw new StdException('invalid token');
		}

		return $token;
	}

	public function changePassword(App $app, array $request) {
		$db = $app->getDatabase();
		$token = $this->checkResetToken($app, $request);

		$password = trim($request['password'] ?? '');
		if (!$password) {
			throw new StdException('invalid password');
		}

		$passwordhash = password_hash($password, PASSWORD_DEFAULT);

		$res = $db->update('users', [
			'passwordhash' => $passwordhash
		], [
			'id' => $token['uid']
		]);

		if ($res->errno) {
			throw new StdException($res->error);
		}

		$res = $db->delete('tokens', [
			'id' => $token['id']
		]);

		return true;
	}

	/**
	 * @http get
	 */
	public function userInfo() {}
}
