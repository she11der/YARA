rule ESET_Kobalos
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Léveillé"
		id = "cdffbe3d-c19d-53a8-9051-48affae00c8a"
		date = "2020-11-02"
		modified = "2021-02-01"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/kobalos/kobalos.yar#L32-L56"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "9161d22f9fbb1700dc3121e32104240e34512cb280aaf950aec61513f89061ef"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		any of them
}