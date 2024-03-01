rule SIGNATURE_BASE_Googlebot_Useragent : FILE
{
	meta:
		description = "Detects the GoogleBot UserAgent String in an Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "621532ac-fc0b-5118-84b0-eac110693320"
		date = "2017-01-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_suspicious_strings.yar#L17-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fa6cc3625d3740b91d7f1193cea0bdb621ae9445e42300123b01e322f715b976"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii
		$fp1 = "McAfee, Inc." wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and $x1 and not 1 of ($fp*))
}
