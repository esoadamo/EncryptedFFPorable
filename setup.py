from distutils.core import setup
import py2exe
 
setup(
    console=['encrypted_profile.py'],
    options={
        'py2exe': {
            'packages': ['rsa', 'pyaes']
        }
    }
)
