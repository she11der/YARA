rule SIGNATURE_BASE_Molerats_Jul17_Sample_1___FILE
{
	meta:
		description = "Detects Molerats sample - July 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "b5277255-3ced-5dc5-9490-c5829a0c248b"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_molerats_jul17.yar#L11-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1b7f00dfb83f5da46663d94f238b55e375743edbdb01701a78922b87c72c518a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"

	strings:
		$s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}