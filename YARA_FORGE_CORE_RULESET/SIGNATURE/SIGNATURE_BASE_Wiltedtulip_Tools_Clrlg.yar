import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Tools_Clrlg : FILE
{
	meta:
		description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "6957c97d-2c2d-50ac-8fd5-2f299fc7b5c8"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L31-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "003f711ac6f2308f2bdc638da7c654686e7402db7b3837120168e5a99b774537"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"

	strings:
		$s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
		$s2 = "wevtutil.exe cl %1" fullword ascii

	condition:
		filesize <1KB and 1 of them
}
