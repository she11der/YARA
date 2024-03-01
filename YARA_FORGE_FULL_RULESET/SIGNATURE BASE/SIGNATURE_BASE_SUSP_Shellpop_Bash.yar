import "pe"

rule SIGNATURE_BASE_SUSP_Shellpop_Bash
{
	meta:
		description = "Detects susupicious bash command"
		author = "Tobias Michalski"
		id = "ea9c2491-8b25-5ba4-9968-22a45d6e6491"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4399-L4411"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "31633e84ecc1885d041f36399bb5b10915f6371a37d2995f369eb8c0294f1596"
		score = 65
		quality = 85
		tags = ""
		hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"

	strings:
		$ = "/bin/bash -i >& /dev/tcp/" ascii

	condition:
		1 of them
}
