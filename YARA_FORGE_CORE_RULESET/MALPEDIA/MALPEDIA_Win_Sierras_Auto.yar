rule MALPEDIA_Win_Sierras_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "605d6eab-f109-574e-b05c-a9ae83591a9c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sierras"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sierras_auto.yar#L1-L167"
		license_url = "N/A"
		logic_hash = "a564c7fabb45cfabecce73bb6168ff37faec379b0995b89fe8defbd9d38cf80c"
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
		$sequence_0 = { f3a4 8d8c2424050000 8d942430080000 51 }
		$sequence_1 = { 56 8bf1 57 68???????? 8d4604 50 }
		$sequence_2 = { 50 8d45e0 50 e8???????? eb0f 8b4dec }
		$sequence_3 = { e8???????? 50 8d442430 50 8d8c24ec000000 }
		$sequence_4 = { 0f8480030000 8b4dfc ff4df8 0fb611 8bcf }
		$sequence_5 = { 7507 e8???????? eb05 e8???????? 0175f0 }
		$sequence_6 = { 8bf1 e8???????? 8b8698010000 5e }
		$sequence_7 = { 8bc8 83e103 f3a4 8bbc2410040000 }
		$sequence_8 = { 03fb 3b7d10 72b0 8b5df0 834dfcff 8d4de0 }
		$sequence_9 = { 8bf1 33db 6a01 6a78 }
		$sequence_10 = { f2ae f7d1 2bf9 8d942480000000 8bf7 8bd9 8bfa }
		$sequence_11 = { 8bf1 e8???????? 8b8608010000 5e c3 56 }
		$sequence_12 = { 397d08 897dfc 0f8cc0000000 837d0801 7e58 }
		$sequence_13 = { c7401880dd4000 e9???????? 83e00f c70613000000 894648 8b4648 85c0 }
		$sequence_14 = { 58 0fb688c88c4000 6683bc8e7e0a000000 7506 }
		$sequence_15 = { 3bf8 7cce 8b442418 83c520 40 83f803 89442418 }

	condition:
		7 of them and filesize <131072
}
