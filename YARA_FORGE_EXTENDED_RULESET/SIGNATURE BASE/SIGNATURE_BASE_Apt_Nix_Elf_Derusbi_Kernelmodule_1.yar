rule SIGNATURE_BASE_Apt_Nix_Elf_Derusbi_Kernelmodule_1 : FILE
{
	meta:
		description = "Detects Derusbi Backdoor ELF Kernel Module"
		author = "Fidelis Cybersecurity"
		id = "98196ffc-8a6f-5edc-a688-eeb449410b72"
		date = "2016-02-29"
		modified = "2023-05-04"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_turbo_campaign.yar#L51-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fab37e2dbe05c694da6e428aa922747b276c2827cbbd2b6c8002f0cc30c2870c"
		score = 75
		quality = 85
		tags = "FILE"

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
		$s12 = "vermagic="
		$s13 = "current_task"
		$s14 = "sock_release"
		$s15 = "module_layout"
		$s16 = "init_uts_ns"
		$s17 = "init_net"
		$s18 = "init_task"
		$s19 = "filp_open"
		$s20 = "__netlink_kernel_create"
		$s21 = "kfree_skb"

	condition:
		uint32(0)==0x464c457f and all of them
}
