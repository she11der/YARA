rule MALPEDIA_Win_Mbrlock_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "daa9848d-eee7-57fa-b29b-86c1367b5691"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlock"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mbrlock_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "7a0dcc0e30832e7304006fa42a5eab963221d66f36bad91605b77fec2d75b555"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 898e94000000 8945e4 e9???????? 8b5d10 8b7d14 8b4e0c }
		$sequence_1 = { 8bcb bd01000000 e8???????? 8bf0 85f6 0f84f8000000 85ed }
		$sequence_2 = { 8b4de8 8bc1 25ffff0000 2d4c450000 7475 83e802 7433 }
		$sequence_3 = { e8???????? 8b45ec 3d00800000 74ab 8b450c 8d5594 }
		$sequence_4 = { 894e30 50 53 8bcf e8???????? 85c0 7505 }
		$sequence_5 = { e8???????? 8bd0 85d2 7424 817f1402000080 7519 8b470c }
		$sequence_6 = { 8bcf e8???????? 8b4d08 894144 8b45ec 85c0 7505 }
		$sequence_7 = { 33d2 8bd9 668b144590844a00 8b4c2430 8954242c 8bc1 be02000000 }
		$sequence_8 = { 68ac5e0110 56 50 53 8bcf e8???????? }
		$sequence_9 = { a3???????? 39a81c010000 7405 8b4010 eb02 33c0 ffd0 }

	condition:
		7 of them and filesize <2031616
}
