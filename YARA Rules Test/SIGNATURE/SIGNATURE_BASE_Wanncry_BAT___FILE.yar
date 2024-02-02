rule SIGNATURE_BASE_Wanncry_BAT___FILE
{
	meta:
		description = "Detects WannaCry Ransomware BATCH File"
		author = "Florian Roth (Nextron Systems)"
		id = "0929f0de-28ac-5534-a6fd-7b131abda011"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/HG2j5T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_wannacry.yar#L85-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "472c6aa0f1b5229d639ef347ea39947d3fd292cda3c4086e29a19b64daad4f3f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"

	strings:
		$s1 = "@.exe\">> m.vbs" ascii
		$s2 = "cscript.exe //nologo m.vbs" fullword ascii
		$s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
		$s4 = "echo om.Save>> m.vbs" fullword ascii

	condition:
		( uint16(0)==0x6540 and filesize <1KB and 1 of them )
}