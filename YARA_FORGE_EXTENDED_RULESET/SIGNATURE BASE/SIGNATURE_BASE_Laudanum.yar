rule SIGNATURE_BASE_Laudanum : FILE
{
	meta:
		description = "Laudanum Injector Tools - file laudanum.php"
		author = "Florian Roth (Nextron Systems)"
		id = "8c836aba-3644-5914-a3ff-937d0a6cd378"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L228-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		logic_hash = "53caad87d22b5f13e5b7be8720baa1d436cc57d8062ec5d557df8524a2ccfb68"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "public function __activate()" fullword ascii
		$s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii

	condition:
		filesize <5KB and all of them
}
