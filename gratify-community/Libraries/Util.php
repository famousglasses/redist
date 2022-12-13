<?php

namespace App\Libraries;
use Gratify\StdException;

class Util {
	public static function isDateOlderThan(int $date, int $days): bool {
		$diff = time() - $date;
		return $diff / 60 / 60 / 24 >= $days;
	}

	public static function rebuildIdToken(string $id_token, array $changes) {
		$id_decoded = base64_decode($id_token);

		if (!$id_decoded) {
			throw new StdException('invalid id token');
		}

		$id_vals = json_decode($id_decoded, true);

		if (!$id_vals) {
			throw new StdException('invalid id token');
		}

		foreach ($changes as $key => $val) {
			if (isset($id_vals[$key])) {
				$id_vals[$key] = $val;
			}
		}

		$id_token = base64_encode(json_encode($id_vals));

		return $id_token;
	}

	public static function url(string $path = '', array $params = [], bool $include_domain = true) {
		if (empty(trim($path))) {
			$path = '/';
		}

		if (strpos($path, 'http:') === 0) {
			if (!filter_var($path, FILTER_VALIDATE_URL)) {
				throw new StdException('invalid path' . $path);
			}
		} else {
			if (!preg_match(Patterns::URL_PATH, $path)) {
				throw new StdException('invalid path');
			}

			if ($include_domain) {
				$path = ltrim($path, '/');
				$domain = _DOMAIN;

				// hack for cli
				if (_DOMAIN == 'localhost' && !empty(getenv('OVERRIDE_DOMAIN'))) {
					$domain = getenv('OVERRIDE_DOMAIN');
				}

				$path = "https://{$domain}/{$path}";
			}
		}

		$parts = explode('?', $path);
		$path = $parts[0];
		$query = $parts[1] ?? '';

		if (!empty($query)) {
			$parts = explode('&', $query);
			$_params = [];
			foreach ($parts as $p) {
				$x = explode('=', $p);
				$_params[$x[0]] = $x[1];
			}

			$params = array_merge($_params, $params);
		}

		$query = (count($params) ? '?' . http_build_query($params) : '');

		return $path . $query;
	}
}

