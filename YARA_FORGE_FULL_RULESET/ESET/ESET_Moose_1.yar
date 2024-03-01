rule ESET_Moose_1
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "4d228de6-ddbf-57c0-a330-5840c4d40dfc"
		date = "2015-04-21"
		modified = "2016-11-01"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/moose/linux-moose.yar#L41-L76"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "8bedac80a1f754ce56294ba9786b62a002aacd074f756724401efc61def127e6"
		score = 75
		quality = 30
		tags = ""
		Author = "Thomas Dupuy"
		Description = "Linux/Moose malware"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s0 = "Status: OK"
		$s1 = "--scrypt"
		$s2 = "stratum+tcp://"
		$s3 = "cmd.so"
		$s4 = "/Challenge"
		$s7 = "processor"
		$s9 = "cpu model"
		$s21 = "password is wrong"
		$s22 = "password:"
		$s23 = "uthentication failed"
		$s24 = "sh"
		$s25 = "ps"
		$s26 = "echo -n -e "
		$s27 = "chmod"
		$s28 = "elan2"
		$s29 = "elan3"
		$s30 = "chmod: not found"
		$s31 = "cat /proc/cpuinfo"
		$s32 = "/proc/%s/cmdline"
		$s33 = "kill %s"

	condition:
		ESET_Is_Elf_PRIVATE and all of them
}
