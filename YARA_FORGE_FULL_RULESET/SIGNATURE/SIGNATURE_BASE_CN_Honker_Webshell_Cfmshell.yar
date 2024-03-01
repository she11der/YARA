rule SIGNATURE_BASE_CN_Honker_Webshell_Cfmshell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
		author = "Florian Roth (Nextron Systems)"
		id = "40d50ddb-2963-5d8e-b93a-bb44a8944229"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L565-L580"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "740796909b5d011128b6c54954788d14faea9117"
		logic_hash = "0767012ec8fd4a18a64eca04d459efb55fafd29ed052dab8a0eb1b8f4ce7aa66"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
		$s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii

	condition:
		filesize <4KB and all of them
}
