# see minemeld.json entry_points['minemeld_prototypes']
def prototypes():
    import os

    return os.path.join(os.path.dirname(__file__), 'prototypes')
