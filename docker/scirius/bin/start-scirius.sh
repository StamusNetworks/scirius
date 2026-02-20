#!/bin/bash

# Copyright(C) 2016 Stamus Networks
# Copyright(C) 2020 Gabor Seljan
#
# Adapted by Raphaël Brogat <rbrogat@stamus-networks.com>
# Designed for Debian
#
# This script comes with ABSOLUTELY NO WARRANTY!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cd /code

set -e

# Logging utility function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

log_success() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1"
}

if [ "$RULESET_MIDDLEWARE" == "appliances" ]; then
    log "Using appliances ruleset middleware"
    cp /code/docker/scirius/scirius/appliance_local_settings.py /code/scirius/local_settings.py
else
    log "Using suricata ruleset middleware"
    cp /code/docker/scirius/scirius/local_settings.py /code/scirius/local_settings.py
fi
cp -rf /ui/* /code/rules/static || true
cp /ui/webpack-stats-ui.prod.json /code/rules/static/webpack-stats-ui.prod.json || true

migrate_db() {
    log "Starting database migration..."

    log "Creating new migrations if needed..."
    if python manage.py makemigrations --noinput; then
        log_success "Migrations created/checked successfully"
    else
        log_error "Failed to create migrations"
        return 1
    fi

    log "Applying migrations to database..."
    if python manage.py migrate --noinput; then
        log_success "Database migrations applied successfully"
    else
        log_error "Failed to apply migrations"
        return 1
    fi

    log "Collecting static files..."
    if python manage.py collectstatic --noinput; then
        log_success "Static files collected successfully"
    else
        log_error "Failed to collect static files"
        return 1
    fi
}

create_db() {
    log "Starting initial database setup..."

    log "Creating new migrations if needed..."
    if python manage.py makemigrations --noinput; then
        log_success "Migrations created successfully"
    else
        log_error "Failed to create migrations"
        return 1
    fi

    log "Running initial database sync..."
    if python manage.py migrate --run-syncdb --noinput; then
        log_success "Database synced successfully"
    else
        log_error "Failed to sync database"
        return 1
    fi

    # Set default superuser credentials
    SUPERUSER_USERNAME="${DJANGO_SUPERUSER_USERNAME:-selks-user}"
    SUPERUSER_EMAIL="${DJANGO_SUPERUSER_EMAIL:-selks-user@selks.com}"
    SUPERUSER_PASSWORD="${DJANGO_SUPERUSER_PASSWORD:-selks-user}"

    log "Checking if superuser '$SUPERUSER_USERNAME' exists..."

    # Check if superuser already exists
    USER_EXISTS=$(python manage.py shell -c "from django.contrib.auth.models import User; print(User.objects.filter(username='$SUPERUSER_USERNAME').exists())" 2>/dev/null | tail -n 1)

    if [ "$USER_EXISTS" = "True" ]; then
        log "Superuser '$SUPERUSER_USERNAME' already exists, skipping creation"
    else
        log "Creating superuser '$SUPERUSER_USERNAME'..."
        if echo "from django.contrib.auth.models import User; User.objects.create_superuser('$SUPERUSER_USERNAME', '$SUPERUSER_EMAIL', '$SUPERUSER_PASSWORD')" | python manage.py shell; then
            log_success "Superuser '$SUPERUSER_USERNAME' created successfully"
        else
            log_error "Failed to create superuser"
            return 1
        fi
    fi

    # Add user to Superuser group if it exists
    log "Adding user to Superuser group..."
    GROUP_ADD_RESULT=$(python manage.py shell -c "
from django.contrib.auth.models import User, Group
try:
    u = User.objects.filter(username='$SUPERUSER_USERNAME').first()
    g = Group.objects.filter(name='Superuser').first()
    if u and g:
        if u not in g.user_set.all():
            g.user_set.add(u)
            print('added')
        else:
            print('already_member')
    else:
        print('not_found')
except Exception as e:
    print('error')
" 2>/dev/null | tail -n 1)

    case "$GROUP_ADD_RESULT" in
        "added")
            log_success "User added to Superuser group"
            ;;
        "already_member")
            log "User already member of Superuser group"
            ;;
        "not_found")
            log "Superuser group not found, skipping group assignment"
            ;;
        *)
            log_error "Failed to add user to Superuser group"
            ;;
    esac

    # Create cache table (idempotent - will not fail if already exists)
    log "Creating cache table..."
    if python manage.py createcachetable my_cache_table 2>&1 | grep -q "already exists"; then
        log "Cache table already exists, skipping creation"
    elif python manage.py createcachetable my_cache_table; then
        log_success "Cache table created successfully"
    else
        log_error "Failed to create cache table"
        return 1
    fi

    log "Adding default rulesets and sources..."
    python manage.py addsource "ETOpen Ruleset" https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz http sigs
    python manage.py addsource "Lateral movement ruleset" https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz http sigs
    python manage.py defaultruleset "Default ruleset"
    python manage.py disablecategory "Default ruleset" stream-events
    python manage.py addsuricata suricata "Suricata" "Default ruleset"

    log "Updating Suricata configuration..."
    if python manage.py updatesuricata; then
        log_success "Suricata updated successfully"
    else
        log_error "Failed to update Suricata"
        return 1
    fi

    log "Add daily refreshing rules for 'Default ruleset'..."
    if python manage.py addrefresh "Default ruleset"; then
        log_success "Daily refreshing rules added successfully"
    else
        log_error "Failed to add refreshing rules"
        return 1
    fi

    log "Collecting static files..."
    if python manage.py collectstatic --noinput; then
        log_success "Static files collected successfully"
    else
        log_error "Failed to collect static files"
        return 1
    fi

    touch /data/scirius.data
    log_success "Initial database setup completed"
}

start() {
    log "Preparing to start Scirius server..."

    log "Collecting static files..."
    if python manage.py collectstatic --noinput; then
        log_success "Static files collected"
    else
        log_error "Failed to collect static files"
        return 1
    fi

    log "Cleaning up stale PID files..."
    rm -f /var/run/suri_reloader.pid

    if [ "$DEBUG" == "True" ]; then
        log "Starting Scirius in DEBUG mode on 0.0.0.0:8000..."
        python manage.py runserver 0.0.0.0:8000
    else
        WORKERS=$(($(nproc --all) * 2 + 1))
        log "Starting Scirius with Gunicorn ($WORKERS workers) on 0.0.0.0:8000..."
        gunicorn -w $WORKERS -t 120 -b 0.0.0.0:8000 scirius.wsgi
    fi
}

log "=== Scirius Docker Entrypoint Starting ==="

if [ ! -e "/data/scirius.data" ]; then
    log "First-time setup detected - initializing database..."
    if create_db; then
        log_success "Database initialization completed"
    else
        log_error "Database initialization failed"
        exit 1
    fi

    log "Resetting Kibana dashboards..."
    if /code/docker/scirius/bin/reset_dashboards.sh; then
        log_success "Dashboards reset completed"
    else
        log_error "Failed to reset dashboards (non-fatal, continuing...)"
    fi
else
    log "Existing installation detected - running migrations..."
    if migrate_db; then
        log_success "Migration completed"
    else
        log_error "Migration failed"
        exit 1
    fi
fi

if [ -n "$KIBANA_RESET_DASHBOARDS" ]; then
    log "KIBANA_RESET_DASHBOARDS is set - resetting dashboards..."
    if /code/docker/scirius/bin/reset_dashboards.sh; then
        log_success "Dashboards reset completed"
    else
        log_error "Failed to reset dashboards (non-fatal, continuing...)"
    fi
fi

log "=== Starting Scirius Application ==="
start
