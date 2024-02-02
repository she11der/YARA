rule SIGNATURE_BASE_Snaketurla_Install_SH___FILE
{
	meta:
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "68775c54-46f8-5d44-ba63-6726d2bb8016"
		date = "2017-05-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_snaketurla_osx.yar#L74-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "019d20ca6632759cf01962d336c22831edc64b6927d8b27d026b76eb118fce02"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "${TARGET_PATH}/installd.sh" ascii
		$s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and all of them )
}