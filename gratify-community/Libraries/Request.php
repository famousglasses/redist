<?php

namespace App\Libraries;
use Gratify\App;
use Gratify\StdException;

class Request {
	/**
	 * Require authenticated session and permission grants.
	 */
	public static function enforceAuth(App $app, string $permit = '') {
		$session = $app->getSession();
		$user_id = $session->get('id');

		if (!$user_id) {
			throw new StdException('access denied');
		}

		if ($permit) {
			$user_permits = $session->get('permits');
			if (!in_array($permit, $user_permits)) {
				if (!in_array('all', $user_permits)) {
					throw new StdException('access denied');
				}
			}
		}

		return $user_id;
	}

	public static function enforceProjectAuth(App $app, int $project_id, string $permit = '') {
		$session = $app->getSession();
		$user_id = $session->get('id');

		if (!$user_id) {
			throw new StdException('access denied');
		}

		$db = $app->getDatabase();

		$res = $db->get('projects', [
			'id' => $project_id,
			'user_id' => $user_id
		]);

		if ($res->num_rows > 0) {
			return $user_id;
		}

		$res = $db->get('collabs', [
			'project_id' => $project_id,
			'user_id' => $user_id
		]);

		if ($res->num_rows == 0) {
			throw new StdException('access denied');
		}

		if ($permit) {
			$user_permits = explode(' ', $res->next()['permit'] ?? '');
			if (!in_array($permit, $user_permits)) {
				if (!in_array('all', $user_permits)) {
					throw new StdException('access denied');
				}
			}
		}

		return $user_id;
	}

	/**
	 * Require guest session (no auth).
	 */
	public static function requireGuest(App $app) {
		if (_CLI) {
			return true;
		}

		$session = $app->getSession();

		if ($session->get('id')) {
			throw new StdException('guest access only');
		}

		return true;
	}

	/**
	 * Check if a method was directly request by the client (as opposed to
	 * being called from elsewhere in the code)
	 */
	public static function calledByClient(string $method) {
		return $method === _FUNCTION;
	}
}

