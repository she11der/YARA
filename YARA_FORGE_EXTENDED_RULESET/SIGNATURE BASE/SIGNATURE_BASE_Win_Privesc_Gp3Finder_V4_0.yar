rule SIGNATURE_BASE_Win_Privesc_Gp3Finder_V4_0 : FILE
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3b310c12-ac69-527b-9503-1486ae5f692c"
		date = "2016-06-02"
		modified = "2023-12-05"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_win_privesc.yar#L10-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7d5618315ae5293ce1aea18d255d08bb007f39a466021fb636605684433da158"
		score = 80
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"

	strings:
		$x1 = "Check for and attempt to decrypt passwords on share" ascii
		$x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
		$x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*)) or ( all of them )
}
