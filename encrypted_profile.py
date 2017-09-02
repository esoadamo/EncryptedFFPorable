import encryption as enc
import getpass
import shutil
from subprocess import Popen
import os
import traceback
import signal

PATH_RSA_KEY = "encrypted_profile_key"
FILES_BACKUP_SUFFIX = ".plain"
DIR_ENCRYPTED_PROFILE = "encrypted_profile"
FILES_ENCRYPTED_DEFAULT = ['bookmarks.html', 'cert8.db', 'cookies.sqlite', 'formhistory.sqlite', 'key3.db',
                           'permissions.sqlite', 'places.sqlite', 'secmod.db', 'sessionstore.js',
                           r'sessionstore-backups\recovery.js', r'sessionstore-backups\recovery.bak',
                           r'sessionstore-backups\previous.js']


def get_parent_dir(file_path): return os.path.abspath(os.path.join(file_path, os.pardir))


def list_dir(directory: str, relative: bool = False, files: bool = True, directories: bool = True,
             max_level: int = -1) -> list:
    """
    Lists all files in directory and subdirectories in absolute path form.
    import os
    :param directory directory to be listed
    :param relative if set to true, does return only relative path to the file, based on source folder
    :param files if set to False, only directories are listed
    :param directories if set to False, only files are listed
    :param max_level: maximum level of subfolder to reach. 0 -> just current folder, -1 -> to the infinity and beyond
    :return if :param directory is directory - list of all files and directories in subdirectories
    :return if :param directory is file - list which contains only this file
    :return otherwise emtpy list
    """
    if relative:
        files_list = list_dir(directory, False, files, directories)
        for i, file in enumerate(files_list):
            files_list[i] = file[len(directory) + 1:]
        return files_list
    directory = os.path.abspath(directory) + os.sep
    if not os.path.isdir(directory):
        if os.path.isfile(directory):
            return [directory]
        return []
    listed_files = []
    for file in os.listdir(directory):
        file_path = directory + file
        if os.path.isdir(file_path):
            if max_level != 0:
                listed_files.extend(list_dir(directory=file_path, relative=relative, files=files,
                                             directories=directories, max_level=max_level - 1))
            if directories:
                listed_files.append(file_path)
        elif files:
            listed_files.append(file_path)
    return listed_files


def main():
    files_encrypted = set()
    if os.path.isdir(DIR_ENCRYPTED_PROFILE):
        files_encrypted.update(list_dir(DIR_ENCRYPTED_PROFILE, directories=False))
    files_encrypted.update([os.path.abspath(DIR_ENCRYPTED_PROFILE) + os.path.sep + file
                            for file in FILES_ENCRYPTED_DEFAULT])
    files_decrypted = [file.replace(DIR_ENCRYPTED_PROFILE, r'Data\profile') for file in files_encrypted]

    key_password = getpass.getpass("Enter you password for the keys: ")
    if not os.path.exists(PATH_RSA_KEY):
        print('Generating new RSA keys')
        key_pub, key_priv = enc.gen_key_files(filename=PATH_RSA_KEY, verbose=True, passphrase=key_password)
    else:
        print("Loading RSA keys")
        key_pub, key_priv = enc.load_key_files(passphrase=key_password, filename=PATH_RSA_KEY)
    del key_password
    print("Keys loaded")

    # Section START: decrypt private files
    for i, file_encrypted in enumerate(files_encrypted):
        if not os.path.exists(file_encrypted):
            continue
        file_decrypted = files_decrypted[i]
        file_backup = file_decrypted + FILES_BACKUP_SUFFIX
        if os.path.isfile(file_decrypted):
            print('Backing up ' + os.path.basename(file_decrypted))
            shutil.copy(file_decrypted, file_backup)
        print('%d/%d Decrypting %s' % (i + 1, len(files_encrypted), file_encrypted))
        enc.decrypt_file(file_encrypted, file_decrypted, key_pub, key_priv)
    print('All files decrypted')
    del key_priv
    # Section END: decrypt private files

    # Section START: launch firefox
    print('Launching FirefoxPortable')
    pro = Popen(["FirefoxPortable.exe", "-no-remote"])
    # noinspection PyBroadException
    try:
        pro.wait()
        print('Firefox terminated')
    except:
        print(traceback.format_exc())
        # noinspection PyBroadException
        try:
            os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
        except:
            print(traceback.format_exc())
    # Section END: launch firefox

    # Section START: encrypt private files
    for i, file_encrypted in enumerate(files_encrypted):
        file_decrypted = files_decrypted[i]
        file_backup = file_decrypted + FILES_BACKUP_SUFFIX
        if not os.path.isfile(file_decrypted):
            print('Skipping ' + file_decrypted)
            continue
        if not os.path.isdir(get_parent_dir(file_encrypted)):
            os.makedirs(get_parent_dir(file_encrypted))
        print('%d/%d Encrypting %s' % (i + 1, len(files_encrypted), file_encrypted))
        enc.encrypt_file(file_decrypted, file_encrypted, key_pub)
        os.remove(file_decrypted)
        if os.path.isfile(file_backup):
            print('Recovering backup ' + os.path.basename(file_decrypted))
            shutil.move(file_backup, file_decrypted)
    print('All files encrypted')
    # Section END: encrypt private files


if __name__ == '__main__':
    main()
