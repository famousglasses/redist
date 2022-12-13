<?php

namespace App\Libraries;

class Patterns {
	const ROLE = '/^[a-z][\w-]{2,24}$/';
	const SCOPE = '/^([\w:]+ ?)+$/';
	const RESOURCE_NAME = '/^[a-z][ \w\.\-]+$/i';
	const RESOURCE_NAME_NOSPACE = '/^[a-z][\w\.\-]+$/i';
	const INVITE_CODE = '/^[a-z0-9]{6,12}$/i';
	const DOMAIN_LIST = '/^(([a-z\d\.-]+\.)?[a-z\d-]+\.[a-z\d]+,?)+$/i';
	const URL_PATH = '/^\/?([\w\d-]+\/?)*$/';
	const HEADER_AUTHORIZATION = '/^[a-z]+ [a-z\d\+\/\.=-]+$/i';
}
