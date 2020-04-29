import requests
from settings import API_HEADERS, API_URL
from flask import current_app as app


def get_lungo_person(person_id):
    """Resolve name and email by person id
    @TODO Remove
    """
    try:
        r = requests.get('{}/persons/{}?projection={{"full_name": 1, "address": 1}}'.format(API_URL, person_id),
                         headers=API_HEADERS)

        if r.status_code == 200:

            resp = r.json()

            try:
                email = resp.get('address', {}).get('email')[0]
            except Exception as e:
                app.logger.exception('Could not get email adress from Lungo data')
                email = ''

            return resp.get('full_name', 'Ukjent Navn'), email

    except Exception as e:
        app.logger.exception('Could not get user from Lungo')

    return 'Ukjent Navn', ''


def get_activities(person_id):
    activities = []

    # resp = requests.get('%s/ka/members/activities/member?aggregate={"$person_id": %s}' % (API_URL, person_id),
    resp = requests.get('%s/persons/%s?projection={"memberships":1}' % (API_URL, person_id),
                        headers=API_HEADERS)

    if resp.status_code == 200:
        resp_json = resp.json()
        # for item in resp_json.get('_items', []):
        #    if item.get('_id', None) in PATHNAMES.keys():
        #        activities.append(PATHNAMES[item.get('_id')])
        activities = [x['activity'] for x in resp_json.get('memberships', [])]

        return True, activities

    return False, activities


def get_melwin_id(person_id):
    melwin_id = None

    resp = requests.get('{}/translate/persons?where={{"person_id":{}}}'.format(API_URL, person_id),
                        headers=API_HEADERS)

    if resp.status_code == 200:
        resp_json = resp.json()

        melwin_id = resp_json.get('_items', [])[0].get('melwin_id', None)

        if melwin_id is not None:
            return True, melwin_id

    return False, melwin_id
