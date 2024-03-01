rule SIGNATURE_BASE_URL_File_Local_EXE : FILE
{
	meta:
		description = "Detects an .url file that points to a local executable"
		author = "Florian Roth (Nextron Systems)"
		id = "8b157e98-7b69-5649-b1d8-40bd6b685bf6"
		date = "2017-10-04"
		modified = "2023-12-05"
		reference = "https://twitter.com/malwareforme/status/915300883012870144"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_to_local_exe.yar#L1-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b85b723142f52ade68f6eb8ba54bb7dffafce0df6d1ae8a7c08b3ce621ccadd4"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[InternetShortcut]" ascii wide fullword
		$s2 = /URL=file:\/\/\/C:\\[^\n]{1,50}\.exe/

	condition:
		filesize <400 and all of them
}
