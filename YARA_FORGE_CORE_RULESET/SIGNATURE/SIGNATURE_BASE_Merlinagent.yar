rule SIGNATURE_BASE_Merlinagent
{
	meta:
		description = "Detects Merlin agent"
		author = "Hilko Bengen"
		id = "92346a3f-dce4-58db-893b-b7797fa20029"
		date = "2017-12-26"
		modified = "2023-12-05"
		reference = "https://github.com/Ne0nd0g/merlin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_merlin_agent.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "21743230556cc11a78942de30be476ad8e73731bbda9a4feb83bd8140a703d01"
		score = 75
		quality = 85
		tags = ""
		filetype = "pe, elf, mach"

	strings:
		$x1 = "Command output:\x0d\x0a\x0d\x0a%s"
		$x2 = "[-]Connecting to web server at %s to update agent configuration information."
		$x3 = "[-]%d out of %d total failed checkins"
		$x4 = "[!}Unknown AgentControl message type received %s"
		$x5 = "[-]Received Agent Kill Message"
		$x6 = "[-]Received Server OK, doing nothing"
		$x7 = "[!]There was an error with the HTTP client while performing a POST:"
		$x8 = "[-]Sleeping for %s at %s"
		$s1 = "Executing command %s %s %s"
		$s2 = "[+]Host Information:"
		$s3 = "\tHostname: %s"
		$s4 = "\tPlatform: %s"
		$s5 = "\tUser GUID: %s"

	condition:
		1 of ($x*) or 4 of them
}
