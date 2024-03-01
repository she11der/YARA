rule MALPEDIA_Win_Divergent_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "14cdfb94-4b91-530e-a0fa-873505b81024"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.divergent"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.divergent_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "60d51f83c6b67d5042579114a766b27aab37221121fff155d69e0a695b8fbbca"
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
		$sequence_0 = { 8bc1 880438 40 3d00010000 7cf5 8b450c }
		$sequence_1 = { 83c418 85db 0f8537ffffff 5f 5e 68???????? ff15???????? }
		$sequence_2 = { 3b4510 7518 ff7510 8b4704 ff750c }
		$sequence_3 = { 85c0 750a 830604 5e 5d e9???????? 33c0 }
		$sequence_4 = { ff15???????? 837e0800 7412 ff7608 ff15???????? ff7608 e8???????? }
		$sequence_5 = { 3bf1 7421 3bf9 741d 3bc1 7419 c1e204 }
		$sequence_6 = { 85db 0f84da000000 3975f4 0f84d1000000 53 e8???????? 8945e4 }
		$sequence_7 = { 5d c3 ff25???????? 55 8bec 837d0800 741f }
		$sequence_8 = { e8???????? 8bf8 83c414 85ff 742c 8b463c ff743054 }
		$sequence_9 = { 0fb6f1 0fb6ca 0fb60406 034510 03c8 81e1ff000080 7908 }

	condition:
		7 of them and filesize <212992
}
