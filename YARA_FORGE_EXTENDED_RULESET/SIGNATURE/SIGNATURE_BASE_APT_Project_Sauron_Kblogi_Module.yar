rule SIGNATURE_BASE_APT_Project_Sauron_Kblogi_Module
{
	meta:
		description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "e1dd4d1a-1089-5897-8f4a-52c7068802fa"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L57-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bba87b17a62fc968e89d4f6d10de06875c6b7f47c8bb7ae3f7932804b23a8e87"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Inject using process name or pid. Default"
		$s2 = "Convert mode: Read log from file and convert to text"
		$s3 = "Maximum running time in seconds"

	condition:
		$x1 or 2 of them
}
