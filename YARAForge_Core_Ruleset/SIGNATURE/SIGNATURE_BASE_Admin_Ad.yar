rule SIGNATURE_BASE_Admin_Ad
{
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "7d87b4f6-3227-53cb-803c-4f9c7327f203"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7536-L7548"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
		logic_hash = "0febd10979a959af73332a8e064a510e949109abf863b5fd0fef19b635968d1d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
		$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"

	condition:
		all of them
}