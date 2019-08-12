"""
Author:         Fred Krenson
Description:    This script will take an existing, signed executable and generate permutations
                related to the security data directory and authenticode signature.  It can swap in
                the signature from another file if there is one with a valid signature to test
                with. For running binaries, it can generate a batch script that will run all
                artifacts at once, or can be configured to run all artifacts as they are generated,
                dropping fewer artifacts to disk.  A command can also be specified to run with the
                generated binaries as its first parameter.

                Supported modes include:
                - security_data_directory:
                    mutates the fields in the optional header related to the security block
                - attribute_certificate_table:
                    mutates the WIN_CERTIFICATE struct fields (minus bCertificate)
                - bcertificate_random:
                    Mutates the actual signature portion of the binary with randomly placed and
                    random quantities of single byte overwrites
                - truncate:
                    Simply removes the entire bCertificate block and then adds it back, byte by byte
                    for every iteration of the count.

                Mutation modes supported include null byte (0x00), ff byte (0xff), and random byte
                replacement.

                More modes may be supported in the future.  Currently it stands that fuzzing
                signature values and then properly re-encoding them with asn1 is not a trivial task
                due to the number of different values to mutate and the levels of nesting involved.
                 So that is being left for a future iteration.
"""

#!python3

import os
import argparse
import struct
import random
import subprocess
import pefile

SUPPORTED_MUTATION_MODES = [
    'security_data_directory',
    'attribute_certificate_table',
    'bcertificate_random',
    'truncate'
]


class Mutator():
    """Class supports mutating signature info from a binary with an existing certificate."""

    def __init__(self, filename, output, force, count, modes):
        """Create the mutator class which parses and mutates filename."""
        # Path to binary to permute
        self.__filename = filename
        # Filename of binary to permute
        self.__basename = os.path.basename(filename)
        # Extension of the file being parsed
        self.__extension = filename.split('.')[-1]
        # Output folder
        self.__output = output
        # Controls number of random permutations
        self.__count = count
        # Used to make a .bat runner script
        self.__output_files = []
        # empty list means all modes.
        self.__modes = modes
        # If set will run this command and provide mutated binary as input.
        self.__run_cmd = ""
        # Creates, runs, deletes each variant as its created if set to true.
        self.__execute_immediately = False
        # Forcefully overwrites output artifacts if they already exist.
        self.__force = force

        # Read the PE file
        stream = open(filename, 'rb')
        self.__data = stream.read()
        stream.close()

        # Parse the PE contents
        self.__pe = pefile.PE(data=self.__data)

        # Only .exe and .dll formats are supported currently
        if not self.__pe.is_exe() and not self.__pe.is_dll():
            raise Exception("File '%s' is not a supported PE." %
                            self.__filename)

        # Record information about the security data directory
        self.__security_data_dir = self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        self.__security_offset = self.__security_data_dir.VirtualAddress
        self.__security_size = self.__security_data_dir.Size

        # If the doesn't have content at the security data directory, then error out.
        if self.__security_data_dir.VirtualAddress == 0:
            raise Exception(
                "File '%s' does not have a security section." % self.__filename)

    def __read_signature_from_file(self, filename):
        """Extract a cert from filename.  Internal method."""
        # Read the PE file
        stream = open(filename, 'rb')
        data = stream.read()
        stream.close()

        # Parse the PE contents
        alt_pe = pefile.PE(data=data)

        # Record information about the security data directory
        security_data_dir = alt_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        security_offset = security_data_dir.VirtualAddress
        security_size = security_data_dir.Size

        # If the new file doesn't have a signature block, then we error out.
        if security_data_dir.VirtualAddress == 0:
            raise Exception(
                "File '%s' does not have a security section." % self.__filename)

        # Return the whole authentocode signature block
        return data[security_offset:security_offset+security_size]

    def replace_signature(self, alt_file):
        """Replace signature in current file with one from alt_file.

        Uses the signature from alt_file and places it into the current binary's contents.
        Primarily done before any mutations occur.

        Warning:  This function assumes that the signature is at the end of the file.
        """
        print("Replacing existing signature with the one from file '%s'" % alt_file)

        new_signature = self.__read_signature_from_file(alt_file)

        # Modify the security data directory to reflect the new size,
        # and then place the signature block at the end of the file.
        self.__security_data_dir.Size = len(new_signature)
        self.__security_size = len(new_signature)
        self.__pe.set_bytes_at_offset(self.__security_offset, new_signature)

    def output_batch_script(self):
        """Generate _run_all.bat in the output folder."""
        # The leading underscore is to help ensure the file shows up before all others.
        output_path = os.path.join(self.__output, "_run_all.bat")

        if os.path.exists(output_path):
            if not self.__force:
                raise Exception(
                    "File '%s' already exists.  "
                    "Please remove or use -f to overwrite." % output_path)
            if os.path.isdir(output_path):
                raise Exception(
                    "Cannot output batch script.  "
                    "Path '%s' exists already and is a directory." % output_path)

        # Open the output file for writing and disable echo
        stream = open(output_path, 'w')
        stream.write("@echo off\n")

        # Process every variant that was produced for every mutation mode that was enabled.
        for file in self.__output_files:

            # The output files are binaries which can be run.
            # This is the default unless run_cmd was specified.
            cmd = file

            # If the user specified a run command, we substitute that in here.
            if self.__run_cmd != "":
                cmd = "%s %s" % (self.__run_cmd, file)

            # Provide output to the user regarding how far the script is in execution
            stream.write("echo Running %s\n" % cmd)

            # Also write this status to a file, however, this
            # file may not have the most recent entry in it.
            stream.write("echo Running %s >> status.txt\n" % cmd)

            # Actually run the command
            stream.write("%s\n" % cmd)

        stream.close()

    def output_pe(self, name):
        """Output PE contents using the pefile object, which should regenerate checksums."""
        output_path = os.path.join(self.__output, name)

        if os.path.exists(output_path):
            if not self.__force:
                raise Exception(
                    "File '%s' already exists.  "
                    "Please remove or use -f to overwrite." % output_path)
            if os.path.isdir(output_path):
                raise Exception(
                    "Cannot output file.  "
                    "Path '%s' exists already and is a directory." % output_path)

        self.__pe.write(filename=output_path)

        # If -rag was specified, we will execute, and
        # then delete this file and not add it to output_files.
        if self.__execute_immediately:
            cmd = output_path
            if self.__run_cmd != "":
                cmd = "%s %s" % (self.__run_cmd, output_path)

            print("Running %s\n" % cmd)
            subprocess.call(cmd)
            os.remove(output_path)

        else:
            # Record this file so that we can add it to the run_all.bat script.
            self.__output_files.append(name)

    def output_data(self, name, data):
        """Output pe file to disk.

        Used instead of output_pe at points where the actual size of the binary must be shortened.
        Pefile fails to properly trim a binary and a normal string must be constructed.  Since this
        is primarily used with truncation, the checksums don't need to be updated since the
        signature blocks are not actually part of the checksum.
        """
        output_path = os.path.join(self.__output, name)

        if os.path.exists(output_path):
            if not self.__force:
                raise Exception(
                    "File '%s' already exists.  "
                    "Please remove or use -f to overwrite." % output_path)

            if os.path.isdir(output_path):
                raise Exception(
                    "Cannot output file.  "
                    "Path '%s' exists already and is a directory." % output_path)

        stream = open(output_path, 'wb', buffering=0)
        stream.write(data)
        stream.close()

        if self.__execute_immediately:
            cmd = output_path
            if self.__run_cmd != "":
                cmd = "%s %s" % (self.__run_cmd, output_path)

            print("Running %s\n" % cmd)
            subprocess.call(cmd)
            os.remove(output_path)

        else:
            # Record this file so that we can add it to the run_all.bat script.
            self.__output_files.append(name)

    def bcertificate_random_handler(self):
        """Randomly edits the entire bcertificate field without regard to its encoding."""
        # Extract the security block for later replacement.
        original_security_block = self.__data[self.__security_offset:
                                              self.__security_offset + self.__security_size]

        # bCertificate is the 4th field, after 1 dword and 2 words.
        bcert_offset = self.__security_offset + (4+2+2)
        bcert_size = self.__security_size - (4+2+2)

        # Randomly permute with 0x00 bytes after the attribute certificate table header.
        for count in range(self.__count):
            self.randomly_modify_buffer(
                bcert_offset,
                bcert_size,
                1,
                # Percentage based on size of the buffer
                max(int((count/self.__count)*bcert_size), 1),
                lambda: 0x00)

            self.output_pe("%s_bcertificate_random_00bytes_%d.%s" %
                           (self.__basename, count, self.__extension))

            # Replace the security block before the next iteration
            self.__pe.set_bytes_at_offset(
                self.__security_offset, original_security_block)

        # Randomly permute with 0xFF bytes after the attribute certificate table header.
        for count in range(self.__count):
            self.randomly_modify_buffer(
                bcert_offset,
                bcert_size,
                1,
                # Percentage based on size of the buffer
                max(int((count/self.__count)*bcert_size), 1),
                lambda: 0xFF)

            self.output_pe("%s_bcertificate_random_FFbytes_%d.%s" %
                           (self.__basename, count, self.__extension))

            # Replace the security block before the next iteration
            self.__pe.set_bytes_at_offset(
                self.__security_offset, original_security_block)

        # Randomly permute with rand bytes after the attribute certificate table header.
        for count in range(self.__count):
            self.randomly_modify_buffer(
                bcert_offset,
                bcert_size,
                1,
                # Percentage based on size of the buffer
                max(int((count/self.__count)*bcert_size), 1),
                lambda: random.randint(0, 255))

            self.output_pe("%s_bcertificate_random_Randbytes_%d.%s" %
                           (self.__basename, count, self.__extension))

            # Replace the security block before the next iteration
            self.__pe.set_bytes_at_offset(
                self.__security_offset, original_security_block)

    def randomly_modify_buffer(self, offset, length, min_num_edits, max_num_edits, value_func):
        """Apply random modifications to a buffer.

        Offset is the starting location in the pe file where the edit(s) should be applied
        min_num_edits will ensure that at least that number of edits is applied, while
        max_num_edits will ensure that no more than that number of edits is applied.  Valuefunc
        should be a method that returns a number between 0-255, because it will be encoded as a
        single byte.  This could be a function that just returns a null byte, or could be a random
        byte.  It is up to the user to decide what the value of the byte will be.
        """
        # Error check some of the parameters.
        if min_num_edits < 0:
            raise Exception("Minimum number of edits cannot be less than 0.")

        if min_num_edits > max_num_edits:
            raise Exception("Minimum number of edits (%d) is > maximum number of edits (%d)." % (
                min_num_edits, max_num_edits))

        num_edits = random.randint(min_num_edits, max_num_edits)

        # Apply exactly num_edits byte modifications.
        # The location itself is randomized based on the size of the buffer.
        for _ in range(num_edits):
            edit_location = random.randint(0, length)
            self.__pe.set_bytes_at_offset(
                offset+edit_location, struct.pack("<B", value_func()))

    def truncate_handler(self):
        """Truncate the WIN_CERTIFICATE struct and slowly add data back.

        Data is added byte by byte for every iteration of count, so during iteration 0 the entire
        WIN_CERTIFICATE struct is stripped, where the 1000th count has the first 1000 bytes of the
        struct present.
        """
        security_data = self.__pe.get_overlay()

        for count in range(self.__count):

            # If count is now bigger than the size of the whole attribute cert block, break.
            if count > (len(security_data) - 8):
                break

            new_size = 8 + count  # Slowly adding bytes on...
            self.__security_data_dir.Size = new_size

            # Due to a few quirks with the pefile library, in order to get the binary
            # to be successfully reconstituted (i.e. have the security data directory
            # field updated), we need to actually call the write() method, not trim().
            # Then we have to *assume* that the truncation must take place at the end
            # of the file.
            output_data = self.__pe.write()
            output_data = output_data[:self.__security_offset+new_size]

            self.output_data("%s_truncate_%d.%s" % (
                self.__basename, count, self.__extension), output_data)

        self.__security_data_dir.Size = self.__security_size

    def security_data_directory_handler(self):
        """Mutate the offset and size field of the security data directory entry."""
        original_security_dir_offset = self.__security_offset
        original_security_dir_size = self.__security_size

        #========================
        # VirtualAddress Mutation
        #========================

        # Null bytes for offset
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0
        self.output_pe("%s_security_data_directory_VirtualAddress_00bytes.%s" % (
            self.__basename, self.__extension))

        # FF bytes for offset
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0xFFFFFFFF
        self.output_pe("%s_security_data_directory_VirtualAddress_FFbytes.%s" % (
            self.__basename, self.__extension))

        # For rand, we'll make 1/2 of the count be random within the valid file size,
        # and the other 1/2 random within a DWORD
        for count in range(self.__count):
            # Random within file size.
            if count < self.__count//2:
                self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = random.randint(
                    1, len(self.__data))

            else:
                self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = random.randint(
                    1, 0xFFFFFFFF)

            self.output_pe("%s_security_data_directory_VirtualAddress_Randbytes_%d.%s" % (
                self.__basename, count, self.__extension))

        # Reset the offset
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = original_security_dir_offset

        #=====================
        # VirtualSize Mutation
        #=====================

        # Null bytes
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0
        self.output_pe("%s_security_data_directory_Size_00bytes.%s" %
                       (self.__basename, self.__extension))

        # FF bytes
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0xFFFFFFFF
        self.output_pe("%s_security_data_directory_Size_FFbytes.%s" %
                       (self.__basename, self.__extension))

        # For rand, we'll make 1/2 of the count be random within the original size,
        # and the other 1/2 random within a DWORD
        for count in range(self.__count):
            # Random within file size.

            if count < self.__count//2:
                self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = random.randint(
                    1, original_security_dir_size)

            else:
                self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = random.randint(
                    1, 0xFFFFFFFF)

            self.output_pe("%s_security_data_directory_Size_Randbytes_%d.%s" % (
                self.__basename, count, self.__extension))

        # Reset the size
        self.__pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = original_security_dir_size

    def attribute_certificate_table_handler(self):
        """Mutate the first 3 fields of the WIN_CERTIFICATE struct."""
        # Extract the security block
        original_security_block = self.__data[self.__security_offset:
                                              self.__security_offset + self.__security_size]

        # dwLength: offset 0
        offset = 0

        # Try 0 length
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<L", 0))
        #self.__pe.write(filename="%s_attribute_certificate_table_dwLength_0.exe" % self.__filename)
        self.output_pe("%s_attribute_certificate_table_dwLength_0.%s" %
                       (self.__basename, self.__extension))

        # Try max length
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<L", 0xFFFFFFFF))
        self.output_pe("%s_attribute_certificate_table_dwLength_FFFFFFFF.%s" % (
            self.__basename, self.__extension))

        # Try random values
        for _ in range(self.__count):
            rand = random.randint(0, 0xFFFFFFFF)
            self.__pe.set_bytes_at_offset(
                self.__security_offset+offset, struct.pack("<L", rand))
            self.output_pe("%s_attribute_certificate_table_dwLength_%08x.%s" % (
                self.__basename, rand, self.__extension))

        # wRevision:  offset 4

        offset = 4

        # Try 0 value
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0))
        self.output_pe("%s_attribute_certificate_table_wRevision_0.%s" %
                       (self.__basename, self.__extension))

        # Try max length
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0xFFFF))
        self.output_pe("%s_attribute_certificate_table_wRevision_FFFF.%s" % (
            self.__basename, self.__extension))

        # Try revision 1
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0100))
        self.output_pe("%s_attribute_certificate_table_wRevision_0100.%s" % (
            self.__basename, self.__extension))

        # Try revision 2
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0200))
        self.output_pe("%s_attribute_certificate_table_wRevision_0200.%s" % (
            self.__basename, self.__extension))

        # Try random values
        for _ in range(self.__count):
            rand = random.randint(0, 0xFFFF)
            self.__pe.set_bytes_at_offset(
                self.__security_offset+offset, struct.pack("<H", rand))
            self.output_pe("%s_attribute_certificate_table_wRevision_%04x.%s" % (
                self.__basename, rand, self.__extension))

        # wCertificateType:  offset 6

        offset = 6

        # Try 0 value
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_0.%s" % (
            self.__basename, self.__extension))

        # Try max value
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0xFFFF))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_FFFF.%s" % (
            self.__basename, self.__extension))

        # Try 1
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0001))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_0001.%s" % (
            self.__basename, self.__extension))

        # Try 2
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0002))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_0002.%s" % (
            self.__basename, self.__extension))

        # Try 3
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0003))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_0003.%s" % (
            self.__basename, self.__extension))

        # Try 4
        self.__pe.set_bytes_at_offset(
            self.__security_offset+offset, struct.pack("<H", 0x0004))
        self.output_pe("%s_attribute_certificate_table_wCertificateType_0004.%s" % (
            self.__basename, self.__extension))

        # Try random values
        for _ in range(self.__count):
            rand = random.randint(0, 0xFFFF)
            self.__pe.set_bytes_at_offset(
                self.__security_offset+offset, struct.pack("<H", rand))
            self.output_pe("%s_attribute_certificate_table_wCertificateType_%04x.%s" % (
                self.__basename, rand, self.__extension))

        # Reset the pe file back to its original state.
        self.__pe.set_bytes_at_offset(
            self.__security_offset, original_security_block)

    def permute(self):
        """Run different permutation modes specified during instantiation."""
        # Seed the random number generator, uses time or OS specific source for its value.
        random.seed()

        # Verify all requested modes are supported before proceeding to fill the user's hard drive.
        if self.__modes != []:
            # We'll run the list through set() to remove duplicates,
            # but also to check for unsupported options.
            mode_set = list(set(self.__modes))
            difference = [
                x for x in mode_set if x not in SUPPORTED_MUTATION_MODES]

            if difference != []:
                raise Exception("Unsupported modes were specified: %s" %
                                ", ".join(difference))

            active_modes = mode_set

        else:
            # Enable all mutation modes
            active_modes = SUPPORTED_MUTATION_MODES

        # Run all active mutator handlers
        for mode in active_modes:
            handler = getattr(self, "%s_handler" % mode.lower(), None)

            if not handler:
                raise Exception(
                    "Mutation mode '%s' was listed as supported but has not been implemented.  "
                    "Please implement method '%s' in file '%s'" % (
                        mode, "%s_handler()" % mode, __file__))

            handler()

    def set_run_cmd(self, cmd):
        """Set the command the _run_all.bat file will use to execute binaries.

        This results in cmd getting executed with the mutated binary filename as input.
        """
        self.__run_cmd = cmd

    def set_execute_immediately(self, mode):
        """Run each variant as it is generated and then remove it.

        mode is a boolean which sets the execute_immediately flag.  This will still output a binary
        for every variation, but it will clean up after each execution to prevent thousands of
        files from being created.
        """
        if not isinstance(mode, bool):
            raise Exception(
                "Execute immediately requires a boolean.  Received: %s" % type(mode))

        self.__execute_immediately = mode


def main():
    """Verify command line parameters, and start permutation."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-b',
        action='store',
        dest='binary',
        help='Path to a binary file.',
        default=None,
        required=True
    )

    parser.add_argument(
        '-o',
        action='store',
        dest='output',
        help='Directory where permuted files are placed.  Default is the current directory.',
        default=".",
        required=False
    )

    parser.add_argument(
        '-r',
        dest='replace_signature',
        help='Replace the authenticode signature in the binary provided with -b with the '
        'signature from this file.  All subsequent mutations will be against the new signature.  '
        'Does not overwrite the existing binary, but new mutations will include the new signature.',
        default=None,
        required=False
    )

    parser.add_argument(
        '-m',
        nargs="+",
        dest='modes',
        help='Enable mutation of specific sections of the binary.  '
        'Not specifying this flag will enable all modes.  Supported modes include: %s.' %
        ", ".join(SUPPORTED_MUTATION_MODES),
        default=[],
        required=False
    )

    parser.add_argument(
        '-c',
        action='store',
        dest='count',
        help='For modes supporting random permutations, this will control the number of distinct '
        'variants generated.  Default is 5.  The amount of random data will increase as the '
        'variants are generated.',
        default=5,
        type=int,
        required=False
    )

    parser.add_argument(
        '-cmd',
        action='store',
        dest='run_cmd',
        help='This will result in the _run_all.bat script executing this program and '
        'providing the mutated binary as input, as opposed to running the mutated binary directly.',
        default="",
        required=False
    )

    parser.add_argument(
        '-rag', '--run-after-generation',
        action='store_true',
        dest='rag',
        help='This option will output, run, and delete each executable variant as it is generated. '
        'Use this if the creation of hundreds, thousands, or even more files on the system is not '
        'desireable.',
        default=False,
        required=False
    )

    parser.add_argument(
        '-f',
        action='store_true',
        dest='force',
        help='Forcefully overwrite any existing output artifact.',
        default=False,
        required=False
    )

    args = parser.parse_args()

    # Error check the arguments.
    if not os.path.isfile(args.binary):
        raise Exception(
            "Binary '%s' does not exist or is not a file." % args.binary)

    if os.path.exists(args.output) and not os.path.isdir(args.output):
        raise Exception(
            "Output directory '%s' exists and isn't a directory." % args.output)

    # Create the output directory if it doesn't exist.
    if not os.path.exists(args.output):
        os.mkdir(args.output)

    print("Using a random mutation count of %d." % args.count)

    # Create the mutation object.  This will test the input file.
    mut = Mutator(args.binary, args.output, args.force, args.count, args.modes)

    # Replace the signature in the binary if requested.
    # Note this operation currently only works if the
    # signature is at the end of the file specified with -b.
    if args.replace_signature:
        mut.replace_signature(args.replace_signature)

    if args.run_cmd:
        mut.set_run_cmd(args.run_cmd)

    mut.set_execute_immediately(args.rag)

    # Generate all permutations.
    mut.permute()

    # Output the script to run all of the binaries.
    if not args.rag:
        mut.output_batch_script()


if __name__ == "__main__":
    main()
