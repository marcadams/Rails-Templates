# Plugins
plugin('web-app-theme', :git => 'git://github.com/pilu/web-app-theme.git')

gem "rspec", :lib => false,  :environment => :test
gem "cucumber", :lib => false,  :environment => :test
gem "webrat", :lib => false,  :environment => :test
gem "rspec-rails", :lib => false,  :environment => :test
gem "thoughtbot-factory_girl", :lib => "factory_girl", :source => "http://gems.github.com", :environment => :test

# Gems
gem('acl9', :lib => "acl9", :source => "http://gemcutter.org")
gem('authlogic', :source => "http://gems.github.com")

rake("gems:install", :sudo => true)

generate(:rspec)
generate(:cucumber)

# Generate the UserSession model for authlogic
generate(:session, "user_session")

# Generate the user model, skipping the migration as we'll create that manually.
generate(:rspec_model, "user", "--skip-migration")
generate(:rspec_model, "role", "--skip-migration")

# Define the CreateUsers migration file
file "db/migrate/#{Time.now.utc.strftime('%Y%m%d%H%M%S')}_create_users.rb",
%q{class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string :login, :null => false
      t.string :email, :null => false
      t.string :crypted_password, :null => false
      t.string :password_salt, :null => false
      t.string :persistence_token, :null => false
      t.string :single_access_token, :null => false
      t.string :perishable_token,    :null => false
      t.integer :login_count, :default => 0, :null => false
      t.datetime :last_request_at
      t.datetime :last_login_at
      t.datetime :current_login_at
      t.string :last_login_ip
      t.string :current_login_ip
      t.timestamps
    end

    add_index :users, :login
    add_index :users, :persistence_token
    add_index :users, :last_request_at
  end

  def self.down
    drop_table :users
  end
end
}

sleep(1)

# Configure the user model to have acts_as_authentic and acts_as_authorization_subject (acl9)
file "app/models/user.rb",
%q{class User < ActiveRecord::Base
  acts_as_authentic
  acts_as_authorization_subject
end
}

# Manually create the Role model (for acl9)
file "app/models/role.rb",
%q{class Role < ActiveRecord::Base
  acts_as_authorization_role
end
}

# Create migration for roles
file "db/migrate/#{Time.now.utc.strftime('%Y%m%d%H%M%S')}_create_roles.rb",
%q{class CreateRoles < ActiveRecord::Migration
  def self.up
    create_table "roles", :force => true do |t|
      t.string   :name,              :limit => 40
      t.string   :authorizable_type, :limit => 40
      t.integer  :authorizable_id
      t.timestamps
    end
  end

  def self.down
    drop_table :roles
  end
end
}

sleep(1)

# Create migration for RolesUsers join
file "db/migrate/#{Time.now.utc.strftime('%Y%m%d%H%M%S')}_roles_users.rb",
%q{class RolesUsers < ActiveRecord::Migration
  def self.up
    create_table "roles_users", :id => false, :force => true do |t|
      t.references  :user
      t.references  :role
      t.timestamps
    end
  end

  def self.down
    drop_table "roles_users"
  end
end
}

# Setup the application controller to provide for logged in and out users
file "app/controllers/application_controller.rb",
%q{class ApplicationController < ActionController::Base
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  # Scrub sensitive parameters from your log
  filter_parameter_logging :password, :password_confirmation
  helper_method :current_user_session, :current_user

  private
  def current_user_session
    return @current_user_session if defined?(@current_user_session)
    @current_user_session = UserSession.find
  end

  def current_user
    return @current_user if defined?(@current_user)
    @current_user = current_user_session && current_user_session.user
  end

  def require_user
    unless current_user
      store_location
      flash[:notice] = "You must be logged in to access this page"
      redirect_to new_user_session_url
      return false
    end
  end

  def require_no_user
    if current_user
      store_location
      flash[:error] = "You must be logged out to access this page"
      redirect_to root_url
      return false
    end
  end

  def store_location
    session[:return_to] = request.request_uri
  end

  def redirect_back_or_default(default)
    redirect_to(session[:return_to] || default)
    session[:return_to] = nil
  end
end
}

# Generate the UserSessions controller
generate(:rspec_controller, "user_sessions")
generate(:rspec_controller, "users")
generate(:rspec_controller, "welcome", "index")

file "app/controllers/users_controller.rb",
%q{class UsersController < ApplicationController
  before_filter :require_no_user, :only => [:new, :create]
  before_filter :require_user, :only => [:edit, :update]

  def new
    @user = User.new
    render :layout => "sign"
  end

  def index
    @users = User.all

    respond_to do |format|
      format.html
    end
  end

  def create
    @user = User.new(params[:user])
    @user.save!

    redirect_to users_path
    flash[:notice] = "User #{@user.login} added!"
  rescue ActiveRecord::RecordInvalid
    render :action => 'new'
  end

  def edit
    @user = @current_user
  end

  def update
    @user = @current_user

    respond_to do |format|
      if @user.update_attributes(params[:user])
        flash[:notice] = "Successfully updated: #{@user.login}"
        format.html { redirect_to(@user) }
      else
        format.html { render :action => "edit" }
      end
    end
  end

  def show
    if current_user
      @user = @current_user
    else
      @user = User.find_by_login(params[:login])
    end
  end
end
}

file "app/controllers/user_sessions_controller.rb",
%q{class UserSessionsController < ApplicationController
  layout "sign"

  before_filter :require_no_user, :only => [:new, :create]
  before_filter :require_user, :only => :destroy

  def new
    @user_session = UserSession.new
  end

  def create
    @user_session = UserSession.new(params[:user_session])
    if @user_session.save
      flash[:notice] = "Login successful!"
      redirect_back_or_default root_url
    else
      render :action => :new
    end
  end

  def destroy
    current_user_session.destroy
    flash[:notice] = "Logout successful!"
    redirect_back_or_default root_url
  end
end
}

rake("db:create:all")
rake("db:migrate")

# Setup routing
route("map.resources :users")
route("map.resource :user_session")
route("map.root :controller => 'welcome', :action => 'index'")
route("map.connect '/login', :controller => 'user_sessions', :action => :new")
route("map.connect '/logout', :controller => 'user_sessions', :action => :destroy")

generate(:theme, "--theme='drastic-dark'")
generate(:theme, "--theme='drastic-dark' --type='sign'")
generate(:themed, "user_sessions")
generate(:themed, "users")

file "app/views/users/_form.html.erb",
%q{<div class="group">
  <%= f.label :login, t("activerecord.attributes.user.login", :default => "Login"), :class => :label %>
  <%= f.text_field :login, :class => 'text_field' %>
  <span class="description">Ex: a simple text</span>
</div>

<div class="group">
  <%= f.label :password, t("activerecord.attributes.user.password", :default => "Password"), :class => :label %>
  <%= f.password_field :password, :class => 'text_field' %>
  <span class="description">Something you'll remember that a script kiddie can't guess</span>
</div>

<div class="group">
  <%= f.label :password_confirmation, t("activerecord.attributes.user.password_confirmation", :default => "Password confirmation"), :class => :label %>
  <%= f.password_field :password_confirmation, :class => 'text_field' %>
  <span class="description">The same as the previous field</span>
</div>

<div class="group navform wat-cf">
  <button class="button" type="submit">
    <%= image_tag("web-app-theme/tick.png", :alt => "#{t("web-app-theme.save", :default => "Save")}") %> <%= t("web-app-theme.save", :default => "Save") %>
  </button>
  <%= link_to "#{image_tag("web-app-theme/cross.png", :alt => "#{t("web-app-theme.cancel", :default => "Cancel")}")} #{t("web-app-theme.cancel", :default => "Cancel")}", users_path, :class => "button" %>
</div>}

file "app/views/user_sessions/new.html.erb",
%q{<h1><%= t("title") %></h1>
<div class="block" id="block-login">
  <h2>Login</h2>
  <div class="content login">
    <div class="flash">
      <% flash.each do |type, message| -%>
      <div class="message <%= type %>">
        <p><%=  message %></p>
      </div>
      <% end -%>
    </div>
    <% form_for @user_session, :url => user_session_path, :html => { :class => "form login" } do |f| %>
      <div class="group wat-cf">
        <div class="left">
          <label class="label right">Login</label>
        </div>
        <div class="right">
          <%= f.text_field :login, :class => 'text_field' %>
        </div>
      </div>
      <div class="group wat-cf">
        <div class="left">
          <label class="label right">Password</label>
        </div>
        <div class="right">
          <%= f.password_field :password, :class => 'text_field' %>
        </div>
      </div>
      <div class="group navform wat-cf">
        <div class="right">
          <button class="button" type="submit">
            <%= image_tag("web-app-theme/key.png", :alt => "#{t("base.login")}") %> <%= t("base.login") %>
          </button>
        </div>
      </div>
    <% end -%>
    <div class="actions-bar wat-cf">
      <div class="actions">
        Fucker
      </div>
    </div>
  </div>
</div>
}

file "spec/spec_helper.rb",
%q{# This file is copied to ~/spec when you run 'ruby script/generate rspec'
# from the project root directory.
ENV["RAILS_ENV"] ||= 'test'
require File.expand_path(File.join(File.dirname(__FILE__),'..','config','environment'))
require 'spec/autorun'
require 'spec/rails'
Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each {|f| require f}

# Uncomment the next line to use webrat's matchers
require 'webrat/integrations/rspec-rails'

# Include the AuthLogic stuff for authorization sake
require 'authlogic/test_case'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir[File.expand_path(File.join(File.dirname(__FILE__),'support','**','*.rb'))].each {|f| require f}

Spec::Runner.configure do |config|
  # If you're not using ActiveRecord you should remove these
  # lines, delete config/database.yml and disable :active_record
  # in your config/boot.rb
  config.use_transactional_fixtures = true
  config.use_instantiated_fixtures  = false
  config.fixture_path = RAILS_ROOT + '/spec/fixtures/'
end
}

file "spec/factories/users.rb",
%q{Factory.define :valid_user, :class => User do |u|
  u.add_attribute :login, "validuser"
  u.add_attribute :email, "validuser@email.com"
  u.add_attribute :password, "password"
  u.add_attribute :password_confirmation, "password"
end

Factory.define :invalid_user_different_passwords, :class => User do |u|
  u.add_attribute :login, "invalidpassworduser"
  u.add_attribute :email, "invalidpassworduser@email.com"
  u.add_attribute :password, "password"
  u.add_attribute :password_confirmation, "p455w0rd"
end
}

file "spec/spec.opts",
%q{--colour
--format specdoc
--loadby mtime
--reverse
}

file "spec/models/user_spec.rb",
%q{require 'spec_helper'

describe User do
  it "should create a new instance given valid attributes" do
    User.create!(Factory.attributes_for(:valid_user))
  end

  it "should not create a new instance given different passwords" do
    @user = Factory.build(:invalid_user_different_passwords)
    @user.should_not be_valid
  end
end
}

run("mkdir spec/support")

file "spec/support/authlogic_helpers.rb",
%q{module AuthlogicHelperMethods

  def valid_user(overrides={})
    options = {:login => "validlogin", :email => "valid@email.com", :password => "password", :password_confirmation => "password"}
    user = new_user(options)
  end

  def current_user(stubs = {})
    @current_user ||= valid_user(stubs)
  end

  def current_user_session(stubs = {}, user_stubs = {})
    @current_user_session ||= mock_model(UserSession, {:user => current_user(user_stubs)}.merge(stubs))
  end

  def login(user_session_stubs = {}, user_stubs = {})
    UserSession.stub!(:find).and_return(current_user_session(user_session_stubs, user_stubs))
  end

  def logout
    @user_session = nil
  end

end
}

# Init GIT
git :init

# Configure .gitignore
run "touch tmp/.gitignore log/.gitignore vendor/.gitignore"
  run %{find . -type d -empty | grep -v "vendor" | grep -v ".git" | grep -v "tmp" | xargs -I xxx touch xxx/.gitignore}
  file '.gitignore', <<-END
.DS_Store
log/*.log
tmp/**/*
config/database.yml
END


# Cleanup default files we won't need
run "rm -rf test"
run "rm README"
run "rm public/index.html"
run "rm public/favicon.ico"
run "rm public/robots.txt"

