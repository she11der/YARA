rule SIGNATURE_BASE_CN_Honker_Webshell_Serv_U_Serv_U : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
		author = "Florian Roth (Nextron Systems)"
		id = "dd37b2c3-e06d-5245-97d7-40e5eeadb76f"
		date = "2015-06-23"
		modified = "2023-01-27"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L1100-L1117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1c6415a247c08a63e3359b06575b36017befc0c0"
		logic_hash = "89cfcbaa38c3b0b6c31af634b4588dcc8bc7a5aa3edac955a162173341d03622"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" ascii
		$s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii
		$s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii

	condition:
		filesize <435KB and all of them
}
