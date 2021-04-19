import argparse
import os

import lsag

parser = argparse.ArgumentParser()
sp = parser.add_subparsers(dest="command")
splist = []   # list to collect subparsers

g = sp.add_parser('generate_keys', help = 'generate new keys for ring signature')
splist.append(g)
g.add_argument('-n', type=int, action='store', help='number of participants in the ring', required=True)
g.add_argument('-k', type=str, action='store', help='path to save [default: ./data]', nargs='?',  const='./data')

s = sp.add_parser('generate_signature', help = 'generate signature for for message')
splist.append(s)
s.add_argument('-i', type=int, action='store', help='number of signer in the ring', required=True)
s.add_argument('-k', type=str, action='store', help='path to public keys [default: ./data/publics.txt]', nargs='?',  const='./data')
s.add_argument('-l', type=str, action='store', help='path to private key [default: ./data/secreti.txt]', nargs='?',  const='./data')
s.add_argument('-m', type=str, action='store', help='message')
s.add_argument('-s', type=str, action='store', help='path to save signature [default: ./data/signature.txt]', nargs='?',  const='./data')

v = sp.add_parser('verify_signature', help = 'verify signature')
splist.append(v)
v.add_argument('-k', type=str, action='store', help='path to public keys [default: ./data/publics.txt]', nargs='?',  const='./data')
v.add_argument('-m', type=str, action='store', help='message')
v.add_argument('-s', type=str, action='store', help='path to signature [default: ./data/signature.txt]', nargs='?',  const='./data')

l = sp.add_parser('linked', help = 'check if signatures is linked')
splist.append(l)
l.add_argument('-s', type=str, action='store', help='path to first signature [default: ./data/signature1.txt]', nargs='?',  const='./data')
l.add_argument('-d', type=str, action='store', help='path to second signature [default: ./data/signature2.txt]', nargs='?',  const='./data')



# collect and display for helps
helps = []
helps.append(parser.format_help())
for p in splist:
   helps.append(p.format_help())
print('\n'.join(helps))
args = parser.parse_args()
if args.command == "generate_keys":
   x, y = lsag.generate_keys(args.n)
   if args.k == None:
      lsag.export_public_keys(y)
      lsag.export_private_keys(x)
   else:
      path = args.k[1:]
      print(path)
      if not os.path.exists(path):
         os.makedirs(path)
      lsag.export_public_keys(y, path)
      lsag.export_private_keys(x, path)

if args.command == "generate_signature":
   if args.k == None:
      y = lsag.import_public_keys()
   else:
      y = lsag.import_public_keys(args.k[1:])
   if args.l == None:
      x = lsag.import_private_key(args.i)
   else:
      x = lsag.import_private_key(args.i, fullpath=args.l[1:])

   signature = lsag.sign(x, args.i, args.m[1:], y)
   if args.s == None:
      lsag.export_signature(y, args.m[1:], signature)
   else:
      path = args.s[1:]
      head, tail = os.path.split(path)
      print(tail)
      print(head)
      if not os.path.exists(head):
         os.makedirs(head)
      lsag.export_signature(y, args.m[1:], signature, folder_name=head, file_name=tail)

if args.command == "verify_signature":
   if args.k == None:
      y = lsag.import_public_keys()
   else:
      y = lsag.import_public_keys(args.k[1:])
   if args.s == None:
      signature = lsag.import_signature()
   else:
      signature = lsag.import_signature(args.s[1:])
   assert(lsag.verify(args.m[1:], y, *signature))

if args.command == "linked":
   if args.s == None:
      signature1 = lsag.import_signature()
   else:
      print(args.s[1:])
      signature1 = lsag.import_signature(args.s[1:])
   if args.d == None:
      signature2 = lsag.import_signature()
   else:
      signature2 = lsag.import_signature(args.d[1:])
   assert(signature1[2] == signature2[2])