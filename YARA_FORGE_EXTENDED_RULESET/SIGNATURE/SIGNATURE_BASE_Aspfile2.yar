import "pe"

rule SIGNATURE_BASE_Aspfile2
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "42bbcc16-a6d7-53d7-8651-1a28c6b26ee8"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1935-L1951"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
		logic_hash = "0fd52e646751b14840f30100382c5171fd001c05110dccb4ac87be9b2c4b6131"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii

	condition:
		all of them
}
