rule SIGNATURE_BASE_Sofacy_AZZY_Backdoor_Implant_1 : FILE
{
	meta:
		description = "AZZY Backdoor Implant 4.3 - Sample 1"
		author = "Florian Roth (Nextron Systems)"
		id = "ec6bf8ca-ccb9-532e-8b0d-1fba59efa2da"
		date = "2015-12-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_dec15.yar#L42-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
		logic_hash = "b6ddf1274ed78db0c7183e3cc8063c01e4d011bc2947ec05449f3fd0df2050e7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\tf394kv.dll" wide
		$s2 = "DWN_DLL_MAIN.dll" fullword ascii
		$s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
		$s4 = "?Applicate@@YGHXZ" ascii
		$s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 2 of them
}
