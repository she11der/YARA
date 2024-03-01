rule TRELLIX_ARC_Apt_Hanover_Foler_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect hanover foler samples"
		author = "Marc Rivero | McAfee ATR Team"
		id = "064b12a1-7a6a-5a19-bc9a-c98c1dbc6631"
		date = "2012-01-05"
		modified = "2020-08-14"
		reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_hangover.yar#L79-L106"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "bd77d7f8af8329dfb0bcc0624d6d824d427fbaf859ab2dedd8629aa2f3b7ae0d"
		logic_hash = "cd2bd6a4c8084c02af5aaba81529cdb67aab7c2db397e2757d383534123c5227"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Hanover"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		$pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		$pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		$pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <480KB and any of them
}
