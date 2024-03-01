rule SIGNATURE_BASE_Sqldbx_Zhs : FILE
{
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "31c49755-f1bd-5ecb-91ff-1040e40983ab"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L198-L217"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"
		logic_hash = "b0215d29c58c252c1717f08135eab65794a99ed669c2225bcba690ae7d7a034c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
		$s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
		$s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
		$s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
		$s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
		$s12 = "mailto:support@sqldbx.com" fullword ascii
		$s15 = "S.last_login_time \"Last Login\", " fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
