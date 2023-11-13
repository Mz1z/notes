# 这个脚本用来移除img/文件夹中没被笔记使用的图片
# 也可以是曾经使用过后来没用了的图片
import os

def get_imgs():
	# 获取所有的图片
	tmp = os.listdir('./img')
	return tmp

def get_notes():
	# 获取所有的笔记文件
	tmp = os.listdir('.')
	# print(tmp)
	_tmp = {}
	for i in tmp:
		if not os.path.isdir(i) and i != __file__:
			with open(i, 'r', encoding='utf-8') as f:
				content = f.read()
			_tmp[i] = content   # 直接读文件内容进缓存
	return _tmp

def verify_img(imgs, notes):
	used = []
	for img in imgs:
		for note, content in notes.items():
			if img in content:
				print('    > find {} in {}.'.format(img,note))
				used.append(img)
				break
	
	print('\n> not used imgs: ')
	for i in imgs:
		if i not in used:
			print(f'    > {i} is not used')

if __name__ == '__main__':
	print('> start')
	imgs = get_imgs()
	print(imgs)
	print('    > total: {} images.\n'.format(len(imgs)))
	notes = get_notes()
	print(notes.keys())
	print('    > total: {} notes.\n'.format(len(notes)))
	verify_img(imgs, notes)
