import requests
from settings import API_HEADERS, API_URL, ACTIVITIES, PATHNAMES


def get_activities(person_id):
    activities = []

    # resp = requests.get('%s/ka/members/activities/member?aggregate={"$person_id": %s}' % (API_URL, person_id),
    resp = requests.get('%s/persons/%s?projection={"activities":1}' % (API_URL, person_id),
                        headers=API_HEADERS)

    if resp.status_code == 200:
        resp_json = resp.json()
        # for item in resp_json.get('_items', []):
        #    if item.get('_id', None) in PATHNAMES.keys():
        #        activities.append(PATHNAMES[item.get('_id')])
        activities = resp_json.get('activities', [27])

        return True, activities

    return False, activities


def get_melwin_id(person_id):
    melwin_id = None

    resp = requests.get('{}/ka/members/{}'.format(API_URL, person_id),
                        headers=API_HEADERS)

    if resp.status_code == 200:
        resp_json = resp.json()

        melwin_id = resp_json.get('MelwinId', None)

        if melwin_id is not None:
            return True, melwin_id

    return False, melwin_id
