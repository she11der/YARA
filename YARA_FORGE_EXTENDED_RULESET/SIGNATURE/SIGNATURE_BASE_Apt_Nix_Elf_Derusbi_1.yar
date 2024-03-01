rule SIGNATURE_BASE_Apt_Nix_Elf_Derusbi_1 : FILE
{
	meta:
		description = "Detects Derusbi Backdoor ELF"
		author = "Fidelis Cybersecurity"
		id = "c825c5d6-1c2f-5ee7-871e-4be3f41d73f7"
		date = "2016-02-29"
		modified = "2023-05-04"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_turbo_campaign.yar#L1-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "61ef65a1500d3def3376a82bc376db451d202d18b03855ee279b6c01757deb2a"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = "LxMain"
		$s2 = "execve"
		$s3 = "kill"
		$s4 = "cp -a %s %s"
		$s5 = "%s &"
		$s6 = "dbus-daemon"
		$s7 = "--noprofile"
		$s8 = "--norc"
		$s9 = "TERM=vt100"
		$s10 = "/proc/%u/cmdline"
		$s11 = "loadso"
		$s12 = "/proc/self/exe"
		$s13 = "Proxy-Connection: Keep-Alive"
		$s14 = "Connection: Keep-Alive"
		$s15 = "CONNECT %s"
		$s16 = "HOST: %s:%d"
		$s17 = "User-Agent: Mozilla/4.0"
		$s18 = "Proxy-Authorization: Basic %s"
		$s19 = "Server: Apache"
		$s20 = "Proxy-Authenticate"
		$s21 = "gettimeofday"
		$s22 = "pthread_create"
		$s23 = "pthread_join"
		$s24 = "pthread_mutex_init"
		$s25 = "pthread_mutex_destroy"
		$s26 = "pthread_mutex_lock"
		$s27 = "getsockopt"
		$s28 = "socket"
		$s29 = "setsockopt"
		$s30 = "select"
		$s31 = "bind"
		$s32 = "shutdown"
		$s33 = "listen"
		$s34 = "opendir"
		$s35 = "readdir"
		$s36 = "closedir"
		$s37 = "rename"

	condition:
		uint32(0)==0x464c457f and all of them
}
