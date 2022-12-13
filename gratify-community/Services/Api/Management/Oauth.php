<?php

namespace App\Services\Api\Management;
use App\Libraries\Patterns;
use Gratify\App;
use Gratify\StdException;

class OAuth {
	const CLIENT_ID_LENGTH = 32;
	const CLIENT_SECRET_LENGTH = 64;

	public function __construct(App $app) {
		if (!_CLI) {
			throw new StdException('access denied');
		}
	}

	public function getClients(App $app, array $request) {
		$filters = $request['filters'] ?? [];
		if (!empty($filters)) {
			if (!is_array($filters)) {
				$filters = json_decode($filters, true);
			}
		}

		if (!is_array($filters)) {
			throw new StdException('invalid filters');
		}

		$db = $app->getDatabase();
		$res = $db->get('auth_clients', $filters);
		return $res->rows();
	}

	public function createClient(App $app, array $request) {
		$name = $app->assert($request['name'] ?? '', 'regex', Patterns::RESOURCE_NAME, 'name');
		$scope = $app->assert($request['scope'] ?? '', 'regex', Patterns::SCOPE, 'scope');
		$redirect_domains = $app->assert($request['redirect_domains'] ?? '', 'regex', Patterns::DOMAIN_LIST, 'redirect domains');
		$client_id = $this->genClientId($app);
		$client_secret = $this->genClientSecret($app);
		$db = $app->getDatabase();
		$res = $this->getClients($app, ['filters' => ['name' => $name]]);

		if (count($res)) {
			throw new StdException("client with name '{$name}' already exists");
		}

		$res = $db->put('auth_clients', [
			'#client_id' => $client_id,
			'@name' => $name,
			'client_secret' => $client_secret,
			'redirect_domains' => $redirect_domains,
			'scope' => $scope
		]);

		if ($res->errno) {
			throw new StdException($res->error);
		} else {
			$res = $db->get('auth_clients', ['id' => $res->last_insert_id]);
			if ($res->num_rows == 0) {
				throw new StdException('insert check failed');
			}
			return $res->next();
		}
	}

	public function editClient(App $app, array $request) {
	}

	public function deleteClient(App $app, array $request) {
	}

	public function rotateSecret(App $app, array $request) {
	}

	private function genClientId(App $app) {
		$keyring = $app->getKeyring();
		$tries = 0;
		$maxtries = 15;
		$id = null;

		do {
			$check = $keyring->nonce(self::CLIENT_ID_LENGTH);
			$db = $app->getDatabase();
			$res = $db->get('auth_clients', ['id' => $check]);

			if ($res->num_rows == 0) {
				$id = $check;
				break;
			}

			$tries++;
		} while ($tries < $maxtries);

		if (empty($id)) {
			throw new StdException('could not generate client id');
		}

		return $id;
	}

	private function genClientSecret(App $app) {
		$keyring = $app->getKeyring();
		$secret = $keyring->nonce(self::CLIENT_SECRET_LENGTH);
		return $secret;
	}
}

