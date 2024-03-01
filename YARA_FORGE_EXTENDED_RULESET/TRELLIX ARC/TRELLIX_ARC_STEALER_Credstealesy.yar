rule TRELLIX_ARC_STEALER_Credstealesy : STEALER
{
	meta:
		description = "Generic Rule to detect the CredStealer Malware"
		author = "IsecG – McAfee Labs"
		id = "90e23ed8-3243-519b-8eb4-9db5902c73d3"
		date = "2015-05-08"
		modified = "2020-08-14"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/when-hackers-get-hacked-the-malware-servers-of-a-data-stealing-campaign/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/stealer/STEALER_credstealer.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "3d007fc0d2e2eb3d8f0c2b86dd01ede482e72f6c67fd6d284d77c47b53021b3c"
		score = 75
		quality = 70
		tags = "STEALER"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Stealer:W32/CredStealer"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide
		$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8}

	condition:
		$my_hex_string and $my_hex_string2
}
