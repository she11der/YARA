rule MALPEDIA_Win_Absentloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9aab04f2-7678-5cf8-8d74-f6db3f7fcf22"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.absentloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.absentloader_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "77496690e6eb66a44354cd3e27ded72ee59f2468546d53e2a80ae68b108dd0bf"
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
		$sequence_0 = { fe81b89406fd 89148d909406fd 8d4dfc e8???????? 5e c9 c3 }
		$sequence_1 = { eb16 66c704375c6e eb0e 66c704375c74 eb06 66c704375c62 83c602 }
		$sequence_2 = { e8???????? c645fc12 8bcb 0f2805???????? 0f1145b4 6a7f }
		$sequence_3 = { 740f 33c0 80b034a606fd2e 40 83f814 72f3 8b0d???????? }
		$sequence_4 = { 8bec 56 ff7508 8bf1 e8???????? c706841e05fd }
		$sequence_5 = { 7408 3a8ac05d05fd 755a 8b06 8a08 40 42 }
		$sequence_6 = { 7e37 68f8aa06fd e8???????? 833d????????ff 59 7523 bffcaa06fd }
		$sequence_7 = { 7417 6827130000 6830f405fd 68341606fd e8???????? 83c40c 837f2c00 }
		$sequence_8 = { c9 c3 6a08 b8a30305fd e8???????? 8bf1 8975ec }
		$sequence_9 = { 84db 743b 8b4608 8378fc00 7432 83ec10 8d4668 }

	condition:
		7 of them and filesize <794624
}
