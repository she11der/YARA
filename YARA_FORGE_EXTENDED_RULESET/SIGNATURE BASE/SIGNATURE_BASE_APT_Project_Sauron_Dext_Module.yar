rule SIGNATURE_BASE_APT_Project_Sauron_Dext_Module
{
	meta:
		description = "Detects strings from dext module - Project Sauron report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "d69373e0-d6ad-5475-8766-06e865620ed8"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L89-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7dbfb3ddfffa6fa65800e07fdcc527650474740afa658567efe46830587cedae"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Assemble rows of DNS names back to a single string of data"
		$x2 = "removes checks of DNS names and lengths (during split)"
		$x3 = "Randomize data lengths (length/2 to length)"
		$x4 = "This cruft"

	condition:
		2 of them
}
