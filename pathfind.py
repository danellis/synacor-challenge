#!/usr/bin/env python
import random

MAX_LENGTH = 12
iterations = 0

grid = [
  ['*', 8, '-', 1],
  [4, '*', 11, '*'],
  ['+', 4, '-', 18],
  [None, '-', 9, '*']
]

def random_path(max_length):
	path = []
	x, y = 0, 3
	while (x, y) != (3, 0):
		op_direction = random_direction(x, y)
		x, y = take_step(x, y, op_direction)

		num_direction = random_direction(x, y)
		x, y = take_step(x, y, num_direction)

		path.append((op_direction, num_direction))
	return path

def random_direction(x, y):
	directions = []
	if x > 0 and (x, y) != (1, 3): directions.append('w')
	if x < 3: directions.append('e')
	if y > 0: directions.append('n')
	if y < 3 and (x, y) != (0, 2): directions.append('s')
	return random.choice(directions)

def take_step(x, y, direction):
	if direction == 'n': y -= 1
	elif direction == 'e': x += 1
	elif direction == 's': y += 1
	elif direction == 'w': x -= 1
	else:
		raise Exception("Unknown direction '%s'" % direction)
	return x, y

def evaluate_path(path):
	x, y, value = 0, 3, 22
	for op_step, num_step in path:
		x, y = take_step(x, y, op_step)
		op = grid[y][x]
		x, y = take_step(x, y, num_step)
		num = grid[y][x]
		if op == '+':
			value += num
		elif op == '-':
			value -= num
		elif op == '*':
			value *= num
		else:
			raise Exception("Unknown op '%s'" % op)
	return value

def valid_path():
	global iterations
	value = 0
	while value != 30:
		path = random_path(MAX_LENGTH)
		value = evaluate_path(path)
		iterations += 1
	return path

def try_paths():
	shortest = '....................'
	while True:
		path = valid_path()
		if len(path) < len(shortest):
			shortest = path
			print len(path), ''.join([d for pair in path for d in pair])
			if len(path) == 6:
				break

try_paths()
print "%s iterations" % iterations
