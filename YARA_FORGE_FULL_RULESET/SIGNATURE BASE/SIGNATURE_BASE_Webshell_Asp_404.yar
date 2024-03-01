rule SIGNATURE_BASE_Webshell_Asp_404
{
	meta:
		description = "Web Shell - file 404.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L608-L621"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"
		logic_hash = "3db951af36ed3d08bc10b4c3fc2e67481f005580fb76f66b6ec5789ed6e2efdb"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"

	condition:
		all of them
}
