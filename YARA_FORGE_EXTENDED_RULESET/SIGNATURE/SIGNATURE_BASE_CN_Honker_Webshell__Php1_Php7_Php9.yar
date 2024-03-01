rule SIGNATURE_BASE_CN_Honker_Webshell__Php1_Php7_Php9 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "cfc2f624-976f-5ff6-bd07-10948b9290bc"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L859-L878"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6ea5b362f8d8f2e99725d4dd4d2ada5c3939a45a3dde0084571600452ab4673c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "c2f4b150f53c78777928921b3a985ec678bfae32"
		hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"

	strings:
		$s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii
		$s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
		$s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii

	condition:
		filesize <300KB and all of them
}
