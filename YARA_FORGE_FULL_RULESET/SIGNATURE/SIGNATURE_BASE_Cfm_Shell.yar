rule SIGNATURE_BASE_Cfm_Shell : FILE
{
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		author = "Florian Roth (Nextron Systems)"
		id = "5308eecf-a59f-5100-ab60-5034c5b73e7e"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_laudanum_webshells.yar#L105-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
		logic_hash = "961eb398422e3c528b886c150f11dcb8a6832f0ea48e20ddc381e1f2740bd0c6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii
		$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii
		$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii

	condition:
		filesize <20KB and 2 of them
}
