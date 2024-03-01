rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php3 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "3000ac40-35de-5d24-85fb-4d105b07c2e7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L619-L634"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e2924cb0537f4cdfd6f1bd44caaaf68a73419b9d"
		logic_hash = "ba3892feacbbe3d7c6b6308a22ca22b19ae84b6490df2c976852260da2a96ca1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii
		$s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii

	condition:
		filesize <8KB and all of them
}
