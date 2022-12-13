<?php

namespace App\BootLoaders;
use App\Libraries\Patterns;
use Gratify\App;

class Session {
	public static function load(App $app) {
		if (_CLI) {
			$uid = @$_REQUEST['UID'];

			if (!empty($uid)) {
				$db = $app->getDatabase();

				// todo info: when using dot notation, object-style values will NOT be automatically decoded
				$res = $db->get('users.id, users.email, users.prefs, roles.name, roles.permit', [
					'id' => $uid,
					'role' => '$roles.name'
				]);

				if ($res->num_rows > 0) {
					$user = $res->next();
					$_SESSION['id'] = $user['id'];
					$_SESSION['role'] = $user['name'];
					$_SESSION['email'] = $user['email'];
					$_SESSION['prefs'] = json_decode($user['prefs'], true); // todo strata should automatically decode objects
					$_SESSION['permits'] = explode(' ', $user['permit']);
				}
			}

			return true;
		}

		$headers = array_change_key_case(getallheaders(), CASE_LOWER);
		$authorization = $headers['authorization'] ?? '';

		if (!empty($authorization)) {
			if (!preg_match(Patterns::HEADER_AUTHORIZATION, $authorization, $matches)) {
				throw new StdException('invalid authorization header');
			}

			$scheme = strtolower($matches[1]);

			if ($scheme != 'bearer') {
				throw new StdException('invalid authorization scheme');
			}

			$token = $matches[2];

			$session = $app->getSession(_SESSION_DRIVER_NONE, [
				'use_cookies' => false
			]);

			if (!$session->start('sid', $token)) {
				throw new StdException('session fault');
			}
		} else {
			$session = $app->getSession(_SESSION_DRIVER_NONE, [
				'use_cookies' => true
			]);

			if (!$session->start()) {
				throw new StdException('session fault');
			}
		}

		return true;
	}
}

