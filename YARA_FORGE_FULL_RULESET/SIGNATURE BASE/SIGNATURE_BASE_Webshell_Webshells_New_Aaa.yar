rule SIGNATURE_BASE_Webshell_Webshells_New_Aaa
{
	meta:
		description = "Web shells - generated from file aaa.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3234-L3249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "68483788ab171a155db5266310c852b2"
		logic_hash = "3c5b9dd86dc790b03a8540b2fb3a717c5ad17d34f366a319faa127479387eed9"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
		$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
		$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"

	condition:
		1 of them
}
