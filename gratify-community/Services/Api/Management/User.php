<?php

namespace App\Services\Api\Management;
use App\Libraries\Patterns;
use Gratify\App;
use Gratify\StdException;

class User {
	public function __construct(App $app) {
		if (!_CLI) {
			throw new StdException('access denied');
		}
	}

	/**
	 * @http post
	 */
	public function createRole(App $app, array $request) {
		$name = $request['name'] ?? '';
		if (empty($name) || !preg_match(Patterns::ROLE, $name)) {
			throw new StdException('invalid name');
		}

		$permit = $request['permit'] ?? '';
		if (empty($permit) || !preg_match(Patterns::SCOPE, $permit)) {
			throw new StdException('invalid permit');
		}

		$db = $app->getDatabase();
		$res = $db->put('roles', [
			'#name' => $name,
			'permit' => $permit
		]);

		if ($res->errno) {
			throw new StdException($res->error);
		}

		return [
			'id' => $res->last_insert_id,
			'name' => $name,
			'permit' => $permit
		];
	}

	/**
	 * @http post
	 */
	public function createUser(App $app, array $request) {
		$username = $request['username'];
		if (!$username || preg_match('/[^\w\.@-]/', $username)) {
			throw new StdException('invalid username');
		}

		$keyring = $app->getKeyring();
		$shell = $app->getShell();
		$password = $request['password'] ?? $keyring->nonce(8);

		if ($password === '') {
			$question = 'Using blank password. Are you sure? [y/n]: ';
			$answer = strtolower($shell->prompt($question));

			if ($answer !== 'y') {
				throw new StdException('quitting due to blank password');
			}
		} else {
			if (!preg_match('/^.{6,128}$/', $password)) {
				throw new StdException('invalid password');
			}
		}

		$email = '';

		if (!isset($request['email'])) {
			if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
				$email = $username;
			}
		} else {
			$email = trim($request['email']);
			if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
				throw new StdException('invalid email');
			}
		}

		$db = $app->getDatabase();

		if (!empty($email)) {
			$res = $db->get('users.id', ['email' => $email]);
			if ($res->num_rows > 0) {
				throw new StdException('email already in use');
			}
		}

		$role = $request['role'] ?? '';

		if (empty($role)) {
			throw new StdException('invalid role');
		} else {
			$res = $db->get('roles', ['name' => $role]);
			if ($res->num_rows == 0) {
				throw new StdException('invalid role');
			}
		}

		$res = $db->put('users', [
			'#username' => $username,
			'password' => password_hash($password,  PASSWORD_DEFAULT),
			'role' => $role,
			'@email' => $email
		]);

		if ($res->errno) {
			throw new StdException($res->error);
		}

		return [
			'id' => $res->last_insert_id,
			'email' => $email,
			'username' => $username,
			'password' => $password
		];
	}
}

