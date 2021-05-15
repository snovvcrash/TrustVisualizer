#!/usr/bin/env python3

##############################################################################
# Author: @harmj0y
#
# Based on: https://github.com/sixdub/DomainTrustExplorer by @sixdub
#
# Description: Uses pyyed (yEd) library to transform PowerView's updated
#              Get-DomainTrustMapping functionality output to graphml
#
# License: BSD 3-clause
##############################################################################

import csv
from os.path import basename, splitext
from argparse import ArgumentParser

import pyyed

parser = ArgumentParser()
parser.add_argument('trust_file', help='trust file in .csv format (generate with PowerView)')
args = parser.parse_args()

if __name__ == '__main__':
	graph = pyyed.Graph()

	with open(args.trust_file, 'r', encoding='utf-8') as fd:
		reader = csv.reader(fd, delimiter=',')
		next(reader, None)

		for row in reader:
			# csv format:
			#   "SourceName","TargetName","TrustType","TrustAttributes","TrustDirection","WhenCreated","WhenChanged"
			sourceName = row[0].strip().lower()
			targetName = row[1].strip().lower()
			trustType = row[2].strip()
			trustAttributes = row[3].strip()
			trustDirection = row[4].strip()

			# if the source and destination domains are the same, skip
			if sourceName == targetName:
				continue

			if trustType == 'MIT':
				# black label for MIT trusts
				ecolor = '#000000'
			else:
				if 'WITHIN_FOREST' in trustAttributes:
					# green label for intra-forest trusts
					ecolor = '#009900'
				elif 'FOREST_TRANSITIVE' in trustAttributes:
					# blue label for inter-forest trusts
					ecolor = '#0000CC'
				elif trustAttributes == '' or any(attr in trustAttributes for attr in ('TREAT_AS_EXTERNAL', 'FILTER_SIDS', 'CROSS_ORGANIZATION')):
					# red label for external trusts
					ecolor = '#FF0000'
				else:
					# violet label for unknown
					print(f'[-] Unrecognized trust attributes between {sourceName} and {targetName} : {trustAttributes}')
					ecolor = '#EE82EE'

			try:
				# add source node to the internal graph
				graph.add_node(sourceName, label=sourceName, shape_fill='#FFCC00')
			# node exists
			except RuntimeWarning:
				pass

			try:
				# add target node to the internal graph
				graph.add_node(targetName, label=targetName, shape_fill='#FFCC00')
			# node exists
			except RuntimeWarning:
				pass

			# add the edges to the graph
			if 'Bidirectional' in trustDirection:
				graph.add_edge(sourceName, targetName, color=ecolor)
			elif 'Outbound' in trustDirection:
				graph.add_edge(targetName, sourceName, color=ecolor)
			elif 'Inbound' in trustDirection:
				graph.add_edge(sourceName, targetName, color=ecolor)
			else:
				print(f'[-] Unrecognized relationship direction between {sourceName} and {targetName} : {trustDirection}' % (sourceName, targetName, trustDirection))

		outputFile = splitext(basename(args.trust_file))[0] + '.graphml'
		graph.write_graph(outputFile)

		print(f'[+] Graphml writte to "{outputFile}"')
		print('[*] Note: green = within forest, red = external, blue = forest to forest, black = MIT, violet = unrecognized')
