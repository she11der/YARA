rule TRELLIX_ARC_Apt_Nix_Elf_Derusbi_Kernelmodule : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the Derusbi ELK Kernel module"
		author = "Marc Rivero | McAfee ATR Team"
		id = "1614a63d-c5d1-5ce1-a5b8-eb48325f60e6"
		date = "2017-05-31"
		modified = "2020-08-14"
		reference = "https://attack.mitre.org/software/S0021/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Derusbi.yar#L63-L105"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "0b86e96ef616e926f0d665e2bd013f2773461483176c68bd5e7c7d059ac13d78"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:ELF/Derusbi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "__this_module"
		$s2 = "init_module"
		$s3 = "unhide_pid"
		$s4 = "is_hidden_pid"
		$s5 = "clear_hidden_pid"
		$s6 = "hide_pid"
		$s7 = "license"
		$s8 = "description"
		$s9 = "srcversion="
		$s10 = "depends="
		$s11 = "vermagic="
		$s12 = "current_task"
		$s13 = "sock_release"
		$s14 = "module_layout"
		$s15 = "init_uts_ns"
		$s16 = "init_net"
		$s17 = "init_task"
		$s18 = "filp_open"
		$s19 = "__netlink_kernel_create"
		$s20 = "kfree_skb"

	condition:
		( uint32(0)==0x4464c457f) and filesize <200KB and all of them
}
