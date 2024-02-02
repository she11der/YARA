rule SIGNATURE_BASE_KINS_DLL_Zeus
{
	meta:
		description = "Match default bot in KINS leaked dropper, Zeus"
		author = "AlienVault Labs aortega@alienvault.com"
		id = "968ada06-c8a1-5053-95de-10aa484231cb"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/arPhm3"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_kins_dropper.yar#L28-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "bd1ebe7976d1f93856b4f8d1d62d8fff68ce6234204da9fbdc233ddbef56864d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$n1 = "%BOTID%" fullword
		$n2 = "%opensocks%" fullword
		$n3 = "%openvnc%" fullword
		$n4 = /Global\\(s|v)_ev/ fullword
		$s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
		$s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
		$s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
		$s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
		$s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"

	condition:
		all of ($n*) and 1 of ($s*)
}