import "pe"

rule SIGNATURE_BASE_Credtheft_MSIL_Adpasshunt_2_1 : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "FireEye"
		id = "44ba09c3-ac0a-58e7-b98c-dedcbf208d00"
		date = "2023-12-12"
		modified = "2023-12-12"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_fireeye_redteam_tools.yar#L845-L861"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6efb58cf54d1bb45c057efcfbbd68a93"
		logic_hash = "a76faa34a1f9cc891aeaa65525c8698e49d5a141854ca0cffb42f06a251bea43"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$pdb1 = "\\ADPassHunt\\"
		$pdb2 = "\\ADPassHunt.pdb"
		$s1 = "Usage: .\\ADPassHunt.exe"
		$s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
		$s3 = "[ADA] Searching for accounts with userpassword attribute"
		$s4 = "[GPP] Searching for passwords now"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and (@pdb2[1]<@pdb1[1]+50) or 2 of ($s*)
}
